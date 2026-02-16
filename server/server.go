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

var logger *slog.Logger
var server *net.UDPConn
var cm = NewClientManager()
var tunDev tun.Device
var ipPool *IpPool
var pendingClients = common.NewConcurrentMap[string, *Client]()
var realToVirtual = common.NewConcurrentMap[string, netip.Addr]()

func main() {
	logger = common.NewLogger(slog.LevelDebug)
	ipPool = NewPool("12.0.0.1/24")
	server = startUdpServer("0.0.0.0:8000")
	defer server.Close()

	var err error
	tunDev, err = common.SetupTunInterface(tunIface, mtu)
	if err != nil {
		panic(err)
	}
	common.SetIpAddress("12.0.0.44/24", tunIface)
	common.EnablePostrouting("12.0.0.0/24")
	go readTun()
	defer DestroyTun(tunIface)

	readClientPackets()
}

func DestroyTun(tunIface string) {
	fmt.Println("defer: destroying TUN")
	tunDev.Close()
	common.DeleteInterface(tunIface)
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

func readTun() {
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

		packet := common.NewTrafficPacket(bufs[0][tunOffset : tunOffset+sizes[0]])
		// fmt.Println("TUN receviedd packet", )
		if !common.FilterPacket(packet, ipPool.prefix) {
			continue
		}
		fmt.Println("packet passed filter")
		// here, the response packet is received from the internet, encrypt it and send back to cllient
		go sendPacketToClient(packet)
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

func processClientPacket(buf []byte, clientAddr *net.UDPAddr) {
	fmt.Println("buffer from client is ", buf[:20])
	clientIp := clientAddr.IP.String() + ":" + strconv.Itoa(clientAddr.Port)

	clientVirtIp, ok := realToVirtual.Load(clientIp)
	if !ok {
		// TODO
	}
	client := cm.GetClient(clientVirtIp)
	var packet common.Packet
	if client != nil {
		packet, _ = common.ParsePacket(buf, client.Key)
	} else {
		packet, _ = common.ParsePacket(buf, nil)
	}

	switch p := packet.(type) {
	case common.KeyExchangePacket:
		{
			logger.Info("Received KeyExchangeMsg from client", slog.String("clientIp", clientIp))

			clientPubKey, err := ecdh.X25519().NewPublicKey(p.Key())
			if err != nil {
				panic(err)
			}

			serverPrivKey, serverPubKey := common.GeneratePubPrivKeys()
			// TODO maybe I should create some confirmation that this was received
			server.WriteToUDP(common.NewKeyExchangePacket(serverPubKey.Bytes()).Bytes(), clientAddr)
			sharedKey, err := serverPrivKey.ECDH(clientPubKey)

			clientVirtualIp := ipPool.Allocate()
			client := Client{
				Addr:      clientAddr,
				Key:       sharedKey,
				LastSeen:  time.Now(),
				VirtualIP: clientVirtualIp,
			}

			fmt.Println("sendding IP", clientVirtualIp.AsSlice())
			fmt.Println("sendidng mask", byte(ipPool.prefix.Bits()))
			realToVirtual.Store(clientIp, clientVirtualIp)
			server.WriteToUDP(
				common.NewVirtualIpPacket(
					clientVirtualIp.AsSlice(),
					[]byte{byte(ipPool.prefix.Bits())},
				).BytesEncrypted(client.Key),
				clientAddr,
			)
			pendingClients.Store(clientIp, &client)
		}
	case common.ClientReadyPacket:
		{
			clientVirtualIp, ok := realToVirtual.Load(clientIp)
			if !ok {
				// TODO
			}

			pendingClient, ok := pendingClients.Load(clientIp)
			if !ok {
				// TODO
			}

			cm.AddClient(clientVirtualIp, pendingClient, func() {
				server.WriteToUDP(common.NewHeartbeatPacket().Bytes(), clientAddr)
				logger.Debug("Heartbeat sent!", slog.String("clientIp", clientIp))
			})

			pendingClients.Delete(clientIp)
			logger.Debug("Client ready!", slog.String("clientIp", clientIp))
		}
	case common.TrafficPacket:
		{
			payload := make([]byte, tunOffset+p.DataLen())
			copy(payload[tunOffset:], p.Data())

			// inject packet for OS level routing
			written, err := tunDev.Write([][]byte{payload}, tunOffset)
			if err != nil {
				panic(err)
			}

			fmt.Println("packet written to TUN", written)
			common.PrintParsedPacket(p.Bytes())
		}
	case common.HeartbeatPacket:
		{
			logger.Debug("Heartbeat received!", slog.String("clientIp", clientIp))
		}
	default:
		{
			logger.Debug("Received messsage with unknown type!", slog.String("clientIp", clientIp))
		}
	}
	cm.UpdateLastSeen(clientAddr.AddrPort().Addr())
}

func sendPacketToClient(p common.Packet) {
	common.PrintParsedPacket(p.Data())
	destIp := p.GetDestAddr()
	fmt.Println("send packcet to clcient, ip is", destIp)
	client := cm.GetClient(p.GetDestAddr())
	_, err := server.WriteToUDP(p.BytesEncrypted(client.Key), client.Addr)
	if err != nil {
		logger.Error("Failed to send packet back to client", slog.String("error", err.Error()), slog.String("clientIp", client.Addr.IP.String()))
		return
	}
	logger.Info("Packet sent to client", slog.String("clientIp", client.Addr.IP.String()))
}
