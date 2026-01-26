FROM golang:1.25-alpine

RUN apk add --no-cache bash tcpdump iproute2 curl

RUN go install github.com/air-verse/air@latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY client/ ./client/
COPY common/ ./common/

# RUN go build -o ./client/run ./client

# CMD ["./client/run"]
CMD ["air", "-c", "./client/.air.toml"]
