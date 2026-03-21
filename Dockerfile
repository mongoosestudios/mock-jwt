FROM alpine:latest

Label authors="Mongoose Studios"
COPY mock-jwt /bin/mock-jwt
ENTRYPOINT ["mock-jwt"]
EXPOSE 8888