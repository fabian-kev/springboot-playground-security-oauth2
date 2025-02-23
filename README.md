## Spring Oauth2

This sample project demonstrate how Spring Oauth2 work together.

## Usage

Run the authorization server first then run the resource server and client.
Open any browsers and try to access `localhost:8098/login` this will display registered client which is "Herba"
Login using the credentials `user:user` upon successful login, it will redirect you to the home page `localhost:8089`
Now, there is a simple protected API in the client `localhost:8089/v1/users` you should be able to access that now. If
you try to access that without logging it. You will see an error page due to null pointer exception since the current
principal object is null.

## authorize_request_not_found

Issue that you might encounter when you are using your own authorization server and running in localhost
since you are running at localhost, client and authorization server are under 1 host name which localhost.
The workaround is to set `authorization-uri: http://127.0.0.1:9000/oauth2/authorize` the rest will be using `localhost`
with that a client and authorization server don't use the same host anymore. The authorize_request_not_found happens
because the authorization server overrides the client session. 
