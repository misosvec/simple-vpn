package main

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"strconv"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

// TODO offset 0 nor 4 did not work
const tunOffset = 10
const tunIface = "tun8"
const mtu = 1500
const nonceLenght = 12

func DestroyTun(tun tun.Device, tunIface string) {
	fmt.Println("defer: destroying TUN")
	tun.Close()
	common.DeleteInterface(tunIface)
}

func main() {
	connections := make(map[string][]byte)

	conn := startUdpServer("0.0.0.0:8000")
	defer conn.Close()
	tun := common.CreateTunInterface(tunIface, mtu)
	go readTun(tun)
	defer DestroyTun(tun, tunIface)

	buf := make([]byte, 2048)
	for {
		bytesRead, clientAddr, err := conn.ReadFromUDP(buf)
		clientIp := clientAddr.IP.String() + ":" + strconv.Itoa(clientAddr.Port)
		fmt.Println("bytesRead: ", bytesRead)
		if err != nil {
			fmt.Println("Error reading:", err)
			continue
		}
		// fmt.Printf("Received %d bytes from %v: \n", n, clientAddr, buf[:10])
		switch common.MessageType(buf[0]) {
		case common.KeyExchangeMsg:
			{
				fmt.Println("received KeyExchangeMsg")
				clientPubKey, err := ecdh.X25519().NewPublicKey(buf[1:33])
				if err != nil {
					panic(err)
				}
				sharedKey := exchangeKeys(conn, clientAddr, clientPubKey)
				fmt.Println("server shared key is ", sharedKey)
				connections[clientIp] = sharedKey
				fmt.Printf("clientAddr value=%v pointer=%p\n", clientAddr, clientAddr)
				fmt.Println("address %v and key is %v ", clientAddr, sharedKey)
			}
		case common.PacketMsg:
			{
				fmt.Println("received PackedMsg")
				nonce := buf[1 : 1+nonceLenght]
				key := connections[clientIp]

				decrypted, err := common.Decrypt(nonce, buf[1+nonceLenght:bytesRead], key)
				if err != nil {
					panic(err)
				}
				fmt.Println("bytes readis ", bytesRead)
				fmt.Println("decrypted len is ", decrypted)

				buf := make([]byte, tunOffset+len(decrypted))
				copy(buf[tunOffset:], decrypted)

				written, err := tun.Write([][]byte{buf}, tunOffset)
				if err != nil {
					panic(err)
				}
				fmt.Println("packet written to TUN", written)
				common.PrintParsedPacket(decrypted)
			}
		default:
			{
				fmt.Println("defautl receiviedd")
			}
		}
	}
}

func readTun(tun tun.Device) {
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, mtu)
	sizes := make([]int, 1)

	for {
		// TODO take advantage of batch read
		packetsRead, err := tun.Read(bufs, sizes, tunOffset)
		if err != nil {
			panic(err)
		}

		bytesRead := sizes[0]
		fmt.Println("TUN server packetsRead is: ", packetsRead)
		fmt.Println("tun serverr bytesRead is: ", sizes[0])
		fmt.Println("TUN serrver received packet: ")
		common.PrintParsedPacket(bufs[0][tunOffset : tunOffset+bytesRead])

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
	fmt.Println("Listening on UDP: " + address)

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
