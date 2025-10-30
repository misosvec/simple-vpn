package main

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	fmt.Println("Handling connection...")

	// Make a buffer to hold incoming data
	buf := make([]byte, 1024) // 1KB buffer

	// Read data from the connection
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}

	// Print the received data as a string
	fmt.Printf("Received %d bytes: %s\n", n, string(buf[:n]))
}

func tunHandler() {
	tunDev, err := tun.CreateTUN("utun6", 1500)
	if err != nil {
		panic(err)
	}
	defer tunDev.Close()

	const tunOffset = 4 // macOS utun header

	numBuffers := 10
	bufs := make([][]byte, numBuffers)
	sizes := make([]int, numBuffers)

	for i := 0; i < numBuffers; i++ {
		bufs[i] = make([]byte, tunOffset+1500)
	}

	fmt.Println("Listening on TUN interface utun6...")

	for {
		// Keep reading packets in a loop
		n, err := tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			panic(err)
		}

		for i := 0; i < n; i++ {
			// Each packet is in bufs[i][tunOffset : tunOffset+sizes[i]]
			packet := bufs[i][tunOffset : tunOffset+sizes[i]]

			fmt.Println("server tun packet read: ", packet)
		}
	}
}

func startUdpServer(address string) *net.UDPConn {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	fmt.Println("Listening on UDP :" + address)
	return conn
}

func exchangeKeys(conn *net.UDPConn, clientAddr *net.UDPAddr, clientPubKey *ecdh.PublicKey) []byte {
	serverPrivKey, serverPubKey := common.GeneratePubPrivKeys()
	conn.WriteToUDP(append([]byte{byte(common.KeyExchangeMsg)}, serverPubKey.Bytes()...), clientAddr)
	// conn.Write()
	sharedKey, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		panic(err)
	}
	return sharedKey
}

func main() {
	connections := make(map[*net.UDPAddr][]byte)
	go tunHandler()

	conn := startUdpServer("localhost:8000")
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		fmt.Println("in for loop")
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading:", err)
			continue
		}

		fmt.Printf("Received %d bytes from %v: %s\n", n, clientAddr, string(buf[:n]))
		switch common.MessageType(buf[0]) {
		case common.KeyExchangeMsg:
			{
				fmt.Println("received keyExchangeMsg")
				clientPubKey, err := ecdh.X25519().NewPublicKey(buf[1:33])
				if err != nil {
					panic(err)
				}
				sharedKey := exchangeKeys(conn, clientAddr, clientPubKey)
				fmt.Println("server shared key is ", sharedKey)
				connections[clientAddr] = sharedKey
			}
		case common.PacketMsg:
			{
				fmt.Println("received keyExchangeMsg")
			}

		}

	}
}

// this code can be tested using
// sudo ifconfig utun6 10.0.0.1 10.0.0.2
// ping -c 1 10.0.0.2
