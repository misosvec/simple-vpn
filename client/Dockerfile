FROM golang:1.25-alpine

# Install tcpdump (and a few useful debugging tools)
RUN apk add --no-cache tcpdump iproute2

WORKDIR /app

COPY client .
COPY common .

RUN go mod download

RUN go build -o ./client/run ./client

CMD ["./client/run"]
