package main

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

const tunOffset = 10
const mtu = 1500 // maximum transmission unit = the largest size of single packet
const address = "vpn-server-cont"
const port = 8000
const tunIface = "tun7"
const nonceLength = 12

func main() {
	clientPrivKey, clientPubKey := common.GeneratePubPrivKeys()
	server := connectToServer()
	serverPubKey, err := exchangeKeys(server, clientPubKey)
	if err != nil {
		panic(err)
	}
	sharedKey, err := clientPrivKey.ECDH(serverPubKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("client shared key is ", sharedKey)

	dr, err := common.GetDefaultRoute()
	if err != nil {
		panic(err)
	}

	tun := common.SetupTunInterface(tunIface, mtu)
	common.SetDefaultRoute([]string{"default", "dev", tunIface})
	common.SetIpAddress("12.0.0.2/24", tunIface)
	fmt.Println("after seetup")
	defer RestoreNetworkSettings(tun, dr)
	go readFromVpnServer(server, sharedKey, tun)
	handleOutgoingPackets(tun, sharedKey, server)
}

func connectToServer() net.Conn {
	conn, err := net.Dial("udp", address+":"+strconv.Itoa(port)) // <- fix here
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to server")

	return conn
}

func handleOutgoingPackets(tunDev tun.Device, key []byte, server net.Conn) {
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, mtu)
	sizes := make([]int, 1)

	for {
		// TODO take advantage of batch read
		packetsRead, err := tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			panic(err)
		}

		bytesRead := sizes[0]
		fmt.Println("packetsRead is: ", packetsRead)
		fmt.Println("bytesRead is: ", sizes[0])
		common.PrintParsedPacket(bufs[0][:bytesRead])

		// ONLY encrypt the actual packet data, starting from the offset
		actualPacket := bufs[0][tunOffset : tunOffset+bytesRead]
		nonce, encrypted := common.Encrypt(actualPacket, key)
		fmt.Println("nonce lenght is ", len(nonce))
		fmt.Println("nonce is ", nonce)
		msg := append([]byte{byte(common.PacketMsg)}, nonce...) // append nonce
		msg = append(msg, encrypted...)
		fmt.Println("len msg is ", len(msg))
		server.Write(msg)
	}

}

func readFromVpnServer(server net.Conn, key []byte, tun tun.Device) {
	buf := make([]byte, mtu)
	fmt.Println("CLIENT, readding from server")
	for {
		bytesRead, err := server.Read(buf)

		messageType := common.GetMessageType(buf)
		switch messageType {
		case common.KeyExchangeMsg:
			{
				// TODO
			}
		case common.PacketMsg:
			{
				nonce := buf[1 : 1+nonceLength]
				packet := buf[1+nonceLength : bytesRead]
				decrypted, err := common.Decrypt(nonce, packet, key)
				if err != nil {
					panic(err)
				}

				fmt.Println("received packet from server")
				common.PrintParsedPacket(decrypted)
				tunBuf := make([]byte, tunOffset+len(decrypted))
				copy(tunBuf[tunOffset:], decrypted)

				_, err = tun.Write([][]byte{tunBuf}, tunOffset)
				if err != nil {
					panic(err)
				}

			}

		}

		if err != nil {
			panic(err)
		}
	}

}

func exchangeKeys(server net.Conn, clientPubKey *ecdh.PublicKey) (*ecdh.PublicKey, error) {
	server.Write(append([]byte{byte(common.KeyExchangeMsg)}, clientPubKey.Bytes()...))
	keyLength := len(clientPubKey.Bytes())

	buf := make([]byte, keyLength+1)
	_, err := server.Read(buf)
	if err != nil {
		return nil, err
	}

	if common.GetMessageType(buf) == common.KeyExchangeMsg {
		serverPubKey, err := ecdh.X25519().NewPublicKey(buf[1 : keyLength+1])
		if err != nil {
			return nil, err
		}
		return serverPubKey, nil
	}

	return nil, fmt.Errorf("Failed to exchange encryption keys, try again later.")
}

func RestoreNetworkSettings(tunDevice tun.Device, defaultRoute []string) {
	fmt.Println("before restore")
	printIpRoute()
	tunDevice.Close()
	if defaultRoute != nil {
		common.SetDefaultRoute(defaultRoute)
	}
	fmt.Println("after restore")
	printIpRoute()
}

func printIpRoute() {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}

// docker run --name vpn-client-cont --network vpn-network vpn-client
// this code can be tested using
// sudo ifconfig utun7 10.0.0.1 10.0.0.2
// ping -c 1 10.0.0.2
