package main

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"strconv"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

const macOsTunOffset = 4
const mtu = 1500 // maximum transmission unit = the largest size of single packet
const address = "localhost"
const port = 8000

func connectToServer() net.Conn {
	conn, err := net.Dial("udp", address+":"+strconv.Itoa(port)) // <- fix here
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to server")

	return conn
}

func handlePacket(packet []byte, key []byte, server net.Conn) {
	nonce, encrypted := common.Encrypt(packet, key)
	fmt.Println("client packet encrypted")
	server.Write(append(nonce, encrypted...))
	fmt.Println("client packet written")
}

func handleTun(key []byte, server net.Conn) {
	tunDev, err := tun.CreateTUN("utun7", mtu)
	if err != nil {
		panic(err)
	}

	defer tunDev.Close()

	numBuffers := 10
	bufs := make([][]byte, numBuffers)

	for i := range numBuffers {
		bufs[i] = make([]byte, macOsTunOffset+mtu)
	}

	sizes := make([]int, numBuffers)

	fmt.Println("before for loop")
	for {
		_, err := tunDev.Read(bufs, sizes, macOsTunOffset)
		if err != nil {
			panic(err)
		}

		fmt.Println("packet was read in client")
		go handlePacket(bufs[0], key, server)
	}

}

func exchangeKeys(server net.Conn, clientPubKey *ecdh.PublicKey) *ecdh.PublicKey {
	server.Write(append([]byte{byte(common.KeyExchangeMsg)}, clientPubKey.Bytes()...))
	fmt.Println("client sent key to server")
	buf := make([]byte, len(clientPubKey.Bytes())+1)
	_, err := server.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Println("client received server key")
	serverPubKey, err := ecdh.X25519().NewPublicKey(buf[1:33])
	if err != nil {
		panic(err)
	}
	return serverPubKey
}

func main() {

	// key := common.GenerateKey()
	clientPrivKey, clientPubKey := common.GeneratePubPrivKeys()
	server := connectToServer()
	serverPubKey := exchangeKeys(server, clientPubKey)
	sharedKey, err := clientPrivKey.ECDH(serverPubKey)
	fmt.Println("client shared key is ", sharedKey)
	if err != nil {
		panic(err)
	}
	handleTun(sharedKey, server)

}

// this code can be tested using
// sudo ifconfig utun7 10.0.0.1 10.0.0.2
// ping -c 1 10.0.0.2
