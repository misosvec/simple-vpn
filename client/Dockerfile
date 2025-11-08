FROM golang:1.25-alpine

RUN apk add --no-cache bash tcpdump iproute2 curl

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY client/ ./client/
COPY common/ ./common/

RUN go build -o ./client/run ./client

CMD ["./client/run"]
