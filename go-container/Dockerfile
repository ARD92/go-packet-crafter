FROM golang:1.16-alpine
WORKDIR /app
RUN apk --no-cache --upgrade add net-tools iputils 
RUN apk add build-base
RUN apk --no-cache add make git gcc libtool musl-dev ca-certificates dumb-init 
RUN apk add libpcap-dev
RUN apk add tcpdump
