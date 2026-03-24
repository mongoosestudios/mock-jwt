FROM alpine:latest

LABEL authors="Mongoose Studios"
COPY mock-jwt /bin/mock-jwt
ENTRYPOINT ["mock-jwt"]
EXPOSE 8888
