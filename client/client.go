package main

import (
	"crypto/ecdh"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"time"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

const tunOffset = 10
const mtu = 1500 // maximum transmission unit = the largest size of single packet
const address = "vpn-server-cont"
const port = 8000
const tunIface = "tun7"
const nonceLength = 12

var logger *slog.Logger
var keyLength int
var clientPrivKey *ecdh.PrivateKey
var sharedKey []byte
var clientReady bool = false

func main() {
	logger = common.NewLogger(slog.LevelDebug)
	server := connectToServer()

	tunDev, err := common.SetupTunInterface(tunIface, mtu)
	if err != nil {
		panic(err)
	}
	time.Sleep(100 * time.Millisecond)

	err = common.SetDefaultRoute([]string{"default", "dev", tunIface})
	if err != nil {
		panic(err)
	}

	var clientPubKey *ecdh.PublicKey
	clientPrivKey, clientPubKey = common.GeneratePubPrivKeys()
	server.Write(append([]byte{byte(common.KeyExchangeMsg)}, clientPubKey.Bytes()...))
	keyLength = len(clientPubKey.Bytes())

	dr, err := common.GetDefaultRoute()
	if err != nil {
		panic(err)
	}

	fmt.Println("after seetup")
	defer RestoreNetworkSettings(tunDev, dr)
	go readFromVpnServer(server, tunDev)
	handleOutgoingPackets(tunDev, server)
}

func connectToServer() net.Conn {
	conn, err := net.Dial("udp", address+":"+strconv.Itoa(port)) // <- fix here
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to server")

	return conn
}

func handleOutgoingPackets(tunDev tun.Device, server net.Conn) {
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, mtu)
	sizes := make([]int, 1)

	for {
		// TODO take advantage of batch read
		packetsRead, err := tunDev.Read(bufs, sizes, tunOffset)
		if len(sharedKey) == 0 || !clientReady {
			continue
		}
		if err != nil {
			panic(err)
		}

		bytesRead := sizes[0]
		fmt.Println("packetsRead is: ", packetsRead)
		fmt.Println("bytesRead is: ", sizes[0])

		// ONLY encrypt the actual packet data, starting from the offset
		actualPacket := bufs[0][tunOffset : tunOffset+bytesRead]

		ipVersion := actualPacket[0] >> 4
		if ipVersion == 6 {
			logger.Debug("Dropping IPv6 packet - VPN is IPv4 only")
			continue
		}
		common.PrintParsedPacket(actualPacket)
		nonce, encrypted := common.Encrypt(actualPacket, sharedKey)
		msg := append([]byte{byte(common.PacketMsg)}, nonce...) // append nonce
		msg = append(msg, encrypted...)
		fmt.Println("len msg is ", len(msg))
		server.Write(msg)
	}

}

func readFromVpnServer(server net.Conn, tun tun.Device) {
	buf := make([]byte, mtu)
	fmt.Println("CLIENT, readding from server")
	for {
		bytesRead, err := server.Read(buf)

		messageType := common.GetMessageType(buf)
		switch messageType {
		case common.KeyExchangeMsg:
			{
				fmt.Println("rreceived a key echange from server")
				fmt.Println("buffer is ", buf[0:50])
				fmt.Println("key is ", buf[1:keyLength+1])
				serverPubKey, err := ecdh.X25519().NewPublicKey(buf[1 : keyLength+1])
				if err != nil {
					panic(err)
				}
				sharedKey, err = clientPrivKey.ECDH(serverPubKey)
				fmt.Println("shared key is ", sharedKey)
			}
		case common.VirtualIpMsg:
			{
				assignedIp, ok := netip.AddrFromSlice(buf[1:5])
				ipMasked := netip.PrefixFrom(assignedIp, int(buf[5]))

				if !ok {
					panic("TODO")
				}
				logger.Debug("recevied ip form server", ipMasked.String())
				// out, err := exec.Command("ip", "addr", "show", "dev", "tun7").Output()
				// if err != nil {
				// 	panic(err)
				// }
				// fmt.Println(string(out))
				//
				//
				//
				tunName, err := tun.Name()
				if err != nil {
					panic(err)
				}
				fmt.Println("tun name is ", tunName)
				common.SetIpAddress(ipMasked.String(), tunName)

				clientReady = true
				server.Write(common.NewMessage(common.ClientReadyMsg))
			}
		case common.PacketMsg:
			{
				nonce := buf[1 : 1+nonceLength]
				packet := buf[1+nonceLength : bytesRead]
				decrypted, err := common.Decrypt(nonce, packet, sharedKey)
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
		case common.HeartbeatMsg:
			{
				server.Write(common.NewMessage(common.HeartbeatMsg, []byte("OK")))
				logger.Info("heartbeat sent")
			}
		}

		if err != nil {
			panic(err)
		}
	}

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
