package main

import (
	"net"
)

type Client struct {
	Addr *net.UDPAddr
	Key  []byte
}
