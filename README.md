# Readme
mock-jwt is a small mock JWT server for testing authenticated endpoints in CI/CD Pipelines, or for local development.  It was written exclusively by a human, using no AI.

mock-jwt should be considered to be in beta and UNDER NO CIRCUMSTANCES SHOULD IT BE USED FOR AUTHENTICATION IN PRODUCTION.

Currently only tokens signed with Elliptic Curve algorithms are supported.  This is because implementing RSA signed tokens adds a great deal of complexity, and I don't need them for my use-case.  If you want RSA tokens please create an issue requesting them.  If there is sufficient interest I'll take a look at adding them.

## Installation
// TODO: write installation guide

## How to Use mock-jwt
Multiple command flags are provided to try and ensure it will work in your environment.  You may view them by running ```mock-jwt -h```  The following examples will assume default configuration.

Note: a new signing key is generated each time you start the server.  Settings such as custom claims also do not persist between server restarts.

If you are using mock-jwt in a CI/CD pipeline and need to ensure that it's ready to serve requests, you may poll the ```ready``` endpoint.  A 200 response indicates that the server is up and running.
```bash
curl -v localhost:8888/ready
```
output:
```bash
* Host localhost:8888 was resolved.
* IPv4: 127.0.0.1
*   Trying 127.0.0.1:8888...
* Connected to localhost (127.0.0.1) port 8888
> GET /ready HTTP/1.1
> Host: localhost:8888
> User-Agent: curl/x.x.x
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Thu, 01 January 1970 00:00:00 UTC
< Content-Length: 0

```

To generate a new signed JWT, send a POST request to the ```auth``` endpoint:
```bash
curl -X localhost:8888/auth
```
output:
```json
{
   "token":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30._boQD-Tz4jwBqRF0csjCFA_X9nRE9Pv-E44XzjVt_yjfdpvvRyLKcKZL7_7HEfrSPWzGG5LSDyafn9F7VqTiRQ"
}
```

You can also provide a request body with any claims you would like added to the token:
```bash
curl localhost:8888/auth -d '{"username": "foo", "email": "foo@bar.com"}'
```
output:
```json
{
   "token":"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwidXNlcm5hbWUiOiJmb28ifQ.SGXw8LWFxIbagtMM8hXlpEv2JBDgg2yHPN2Jgrxz4L7MwKKUZi3F_s-XA1bYGYR804McjR3Q0x-LbPVF9nkE4A"
}
```

If you need certain claims (I.E. an email address) to be present in all tokens, POST them to the ```/setclaims endpoint.```  Doing so will include the provided claims in all future tokens generated until the server is shut down.  In case of collision with any claims specified in the request body of a POST request to the auth endpoint, the newly specified claims will be applied over what was set for that request only.
```bash
curl localhost:8888/setclaims -d '{"email":"foo@bar.com"}'
```

To change the custom claims, simply send a new POST request to the ```setclaims``` endpoint.  An empty body will clear the custom claims completely. 


The ```/auth/.well-known/jwks.json``` endpoint will return a JSON Web Key formatted response that should be compliant with RFC7517.  Pointing your authentication validation code at this endpoint should be sufficient to allow it to validate tokens issued by mock-jwt.

```bash
curl localhost:8888/auth/.well-known/jwks.json
```
output:
``` json
{
   "keys":[
      {
         "kty":"EC",
         "use":"sig",
         "key_ops":[
            "verify"
         ],
         "alg":"ES256",
         "kid":"03034178-bb11-447b-9921-46ed40089f97",
         "crv":"P-256",
         "x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY=",
         "y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU="
      }
   ]
}
```
Note that KeyID is a UUID and is re-generated each time the server is started.