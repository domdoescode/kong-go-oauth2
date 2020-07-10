FROM golang:alpine as builder

RUN apk add --no-cache git gcc libc-dev
RUN go get github.com/Kong/go-pluginserver

RUN mkdir /go-plugins
COPY vendor /go/src/
COPY go-google-oauth2.go /go/src/github.com/domudall/kong-go-oauth2/go-google-oauth2.go
RUN go build -buildmode plugin -o /go-plugins/go-google-oauth2.so /go/src/github.com/domudall/kong-go-oauth2/go-google-oauth2.go

FROM kong:2.0

COPY --from=builder /go/bin/go-pluginserver /usr/local/bin/go-pluginserver
RUN mkdir /tmp/go-plugins
COPY --from=builder /go-plugins/go-google-oauth2.so /tmp/go-plugins/go-google-oauth2.so

COPY config.yml /tmp/config.yml

ENV KONG_LOG_LEVEL=debug
ENV KONG_DATABASE=off
ENV KONG_GO_PLUGINS_DIR=/tmp/go-plugins
ENV KONG_DECLARATIVE_CONFIG=/tmp/config.yml
ENV KONG_PLUGINS=bundled,go-google-oauth2
ENV KONG_PROXY_LISTEN=0.0.0.0:8000

USER root
RUN chmod -R 777 /tmp
USER kong
