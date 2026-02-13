package main

import (
	"crypto/ecdh"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

// TODO offset 0 nor 4 did not work
const tunOffset = 10
const tunIface = "tun8"
const mtu = 1500
const nonceLenght = 12

func DestroyTun(tunIface string) {
	fmt.Println("defer: destroying TUN")
	tunDev.Close()
	common.DeleteInterface(tunIface)
}

var logger *slog.Logger
var server *net.UDPConn
var cm ClientManager
var tunDev tun.Device
var ipPool *IpPool
var pendingClients map[string]*Client
var realToVirtual map[string]*netip.Addr

func main() {
	logger = common.NewLogger(slog.LevelDebug)
	ipPool = NewPool("12.0.0.1/24")
	pendingClients = make(map[string]*Client)
	realToVirtual = make(map[string]*netip.Addr)
	server = startUdpServer("0.0.0.0:8000")
	defer server.Close()

	var err error
	tunDev, err = common.SetupTunInterface(tunIface, mtu)
	if err != nil {
		panic(err)
	}
	common.SetIpAddress("12.0.0.1/24", tunIface)
	common.EnablePostrouting("12.0.0.0/24")
	go readTun(server)
	defer DestroyTun(tunIface)

	readClientPackets()
}

func readClientPackets() {
	buf := make([]byte, 2048)
	for {
		bytesRead, clientAddr, err := server.ReadFromUDP(buf)
		if err != nil {
			logger.Error("Failed to read packet from client", slog.String("error", err.Error()))
			continue
		}
		go processClientPacket(buf[:bytesRead], clientAddr)
	}
}

func readTun(conn *net.UDPConn) {
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, mtu)
	sizes := make([]int, 1)

	for {
		// TODO take advantage of batch read
		_, err := tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			logger.Error("Failed to read ")
			panic(err)
		}
		// here, the response packet is received from the internet, encrypt it and send back to cllient
		go sendPacketToClient(bufs[0][tunOffset : tunOffset+sizes[0]])
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

func processClientPacket(packet []byte, clientAddr *net.UDPAddr) {
	clientIp := clientAddr.IP.String() + ":" + strconv.Itoa(clientAddr.Port)
	fmt.Println("client Ip is ", clientIp)
	switch common.MessageType(packet[0]) {
	case common.KeyExchangeMsg:
		{
			logger.Info("Received KeyExchangeMsg from client", slog.String("clientIp", clientIp))
			clientPubKey, err := ecdh.X25519().NewPublicKey(packet[1:33])
			if err != nil {
				panic(err)
			}
			sharedKey := exchangeKeys(server, clientAddr, clientPubKey)
			clientVirtualIp := ipPool.Allocate()

			client := Client{
				Addr:      clientAddr,
				Key:       sharedKey,
				LastSeen:  time.Now(),
				VirtualIP: clientVirtualIp,
			}

			realToVirtual[clientIp] = clientVirtualIp
			fmt.Println("assigned IP is ", clientVirtualIp.String())
			server.WriteToUDP(
				common.NewMessage(
					common.VirtualIpMsg,
					clientVirtualIp.AsSlice(),
					[]byte{byte(ipPool.prefix.Bits())},
				),
				clientAddr,
			)
			pendingClients[clientIp] = &client
		}
	case common.ClientReadyMsg:
		{
			clientVirtualIp := realToVirtual[clientIp]

			fmt.Println("client ready with ip ", clientAddr.String())
			cm.AddClient(*clientVirtualIp, pendingClients[clientIp], server)
			delete(pendingClients, clientIp)
		}
	case common.PacketMsg:
		{
			fmt.Println("received PackedMsg")
			nonce := packet[1 : 1+nonceLenght]
			client := cm.GetClient(*realToVirtual[clientIp])
			fmt.Println("packet msg client is ", client)
			decrypted, err := common.Decrypt(nonce, packet[1+nonceLenght:], client.Key)
			if err != nil {
				panic(err)
			}
			fmt.Println("decrypted len is ", decrypted)

			buf := make([]byte, tunOffset+len(decrypted))
			copy(buf[tunOffset:], decrypted)

			// inject packet for OS level routing
			written, err := tunDev.Write([][]byte{buf}, tunOffset)
			if err != nil {
				panic(err)
			}

			fmt.Println("packet written to TUN", written)
			common.PrintParsedPacket(decrypted)
		}
	case common.HeartbeatMsg:
		{
			cm.UpdateLastSeen(clientAddr.AddrPort().Addr())
			logger.Info("heartbeat received", slog.String("clientIp", clientIp))
		}
	default:
		{
			fmt.Println("defautl receiviedd")
		}
	}
}

func sendPacketToClient(packet []byte) {
	common.PrintParsedPacket(packet)
	destIp, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return
	}
	fmt.Println("send packcet to clcient, ip is", destIp)
	client := cm.GetClient(destIp)
	nonce, encrypted := common.Encrypt(packet, client.Key)
	_, err := server.WriteToUDP(common.NewMessage(common.PacketMsg, nonce, encrypted), client.Addr)
	if err != nil {
		logger.Error("Failed to send packet back to client", slog.String("error", err.Error()), slog.String("clientIp", client.Addr.IP.String()))
		return
	}
	logger.Info("Packet sent to client", slog.String("clientIp", client.Addr.IP.String()))
}
