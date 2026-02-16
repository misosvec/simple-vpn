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
var hostIp netip.Prefix

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
	server.Write(common.NewKeyExchangePacket(clientPubKey.Bytes()).Bytes())
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
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}
	sizes := make([]int, 16)

	for {
		// TODO take advantage of batch read
		packetsRead, err := tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			panic(err)
		}

		if len(sharedKey) == 0 || !clientReady {
			// TODO better
			continue
		}

		for i := range packetsRead {
			packet := common.NewTrafficPacket(bufs[i][tunOffset : tunOffset+sizes[i]])
			if !common.FilterPacket(packet, hostIp) {
				continue
			}

			common.PrintParsedPacket(packet.Data())
			server.Write(packet.BytesEncrypted(sharedKey))
		}

	}

}

func readFromVpnServer(server net.Conn, tun tun.Device) {
	buf := make([]byte, mtu)
	fmt.Println("CLIENT, readding from server")
	for {
		bytesRead, err := server.Read(buf)
		if err != nil {
			panic("TODO")
		}
		packet, err := common.ParsePacket(buf[:bytesRead], sharedKey)
		if err != nil {
			panic("TODO")
		}

		switch p := packet.(type) {
		case common.KeyExchangePacket:
			{
				serverPubKey, err := ecdh.X25519().NewPublicKey(p.Key())
				if err != nil {
					panic(err)
				}
				sharedKey, err = clientPrivKey.ECDH(serverPubKey)
				logger.Debug("Shared key generated!")
			}
		case common.VirtualIPPacket:
			{
				virtAddr, err := p.VirtAddr()
				if err != nil {
					panic("TODO")
				}
				fmt.Println("assigned virt adddess is ", virtAddr)
				common.SetIpAddress(virtAddr.String(), tunIface)
				server.Write(common.NewClientReadyPacket().Bytes())
				clientReady = true
				logger.Debug("VirtualIP set! Client ready!")
			}
		case common.TrafficPacket:
			{
				common.PrintParsedPacket(p.Bytes())
				tunBuf := make([]byte, tunOffset+p.DataLen())
				copy(tunBuf[tunOffset:], p.Data())

				_, err = tun.Write([][]byte{tunBuf}, tunOffset)
				if err != nil {
					panic(err)
				}

			}
		case common.HeartbeatPacket:
			{
				server.Write(common.NewHeartbeatPacket().Bytes())
				logger.Debug("Client sent hearbeat answer!")
			}
		}

		if err != nil {
			panic(err)
		}
	}

}

func RestoreNetworkSettings(tunDevice tun.Device, defaultRoute []string) {
	printIpRoute()
	tunDevice.Close()
	if defaultRoute != nil {
		common.SetDefaultRoute(defaultRoute)
	}
	printIpRoute()
}

func printIpRoute() {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
