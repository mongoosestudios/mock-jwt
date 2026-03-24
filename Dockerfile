FROM alpine:latest

LABEL authors="Mongoose Studios"
COPY mock-jwt /bin/
ENTRYPOINT ["mock-jwt"]
EXPOSE 8888
