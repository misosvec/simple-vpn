FROM golang:1.25-alpine

RUN apk add --no-cache bash tcpdump iproute2 curl

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY server/ ./server/
COPY common/ ./common/

RUN go build -o ./server/run ./server

CMD ["./server/run"]
