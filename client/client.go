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

const macOsTunOffset = 4
const mtu = 1500 // maximum transmission unit = the largest size of single packet
const address = "vpn-server-cont"
const port = 8000
const tunIface = "tun7"

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

	tun := SetupTunInterface(tunIface)
	fmt.Println("after seetup")
	defer RestoreNetworkSettings(tun, dr)
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

func handlePacket(packet []byte, key []byte, server net.Conn) {
	nonce, encrypted := common.Encrypt(packet, key)
	fmt.Println("client packet encrypted")
	server.Write(append(nonce, encrypted...))
	fmt.Println("client packet written")
}

func handleOutgoingPackets(tunDev tun.Device, key []byte, server net.Conn) {
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

		fmt.Printf("packetin TUN was read in client %b\n", bufs[0][0:5])
		go handlePacket(bufs[0], key, server)
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

func SetupTunInterface(tunName string) tun.Device {
	dev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		panic(err)
	}
	err = exec.Command("ip", "link", "set", tunName, "up").Run()
	if err != nil {
		panic(err)
	}
	fmt.Println("ccalling set default")
	err = common.SetDefaultRoute([]string{"default", "dev", tunName})
	if err != nil {
		panic(err)
	}
	return dev
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

// this code can be tested using
// sudo ifconfig utun7 10.0.0.1 10.0.0.2
// ping -c 1 10.0.0.2
