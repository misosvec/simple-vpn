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

var logger *slog.Logger
var server *net.UDPConn
var cm = NewClientManager()
var tunDev tun.Device
var ipPool *IpPool = NewIpPool("12.0.0.1/24")
var pendingClients = common.NewConcurrentMap[string, *Client]()
var realToVirtual = common.NewConcurrentMap[string, netip.Addr]()
var packetChan = make(chan common.IncomingPacket, 2048)
var trafficChan = make(chan common.Packet, 2048)

func main() {
	logger = common.NewLogger(slog.LevelDebug)
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
	go startWorkers(3, packetChan, processClientPacket)
	go startWorkers(3, trafficChan, sendPacketToClient)
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
		packetChan <- common.IncomingPacket{
			Data: buf[:bytesRead],
			Addr: clientAddr,
		}
	}
}

func readTun() {
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}
	sizes := make([]int, 16)

	for {
		// TODO take advantage of batch read
		packetsRead, err := tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			logger.Error("Failed to read ")
			panic(err)
		}

		for i := range packetsRead {
			packet := common.NewTrafficPacket(bufs[i][tunOffset : tunOffset+sizes[i]])
			// fmt.Println("TUN receviedd packet", )
			if !common.FilterPacket(packet, ipPool.prefix) {
				continue
			}
			trafficChan <- packet
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
	fmt.Println("Listening on UDP: " + address)

	return conn
}

func processClientPacket(incP common.IncomingPacket) {
	clientIp := incP.Addr.IP.String() + ":" + strconv.Itoa(incP.Addr.Port)

	clientVirtIp, ok := realToVirtual.Load(clientIp)
	if !ok {
		// TODO
	}
	client := cm.GetClient(clientVirtIp)
	var packet common.Packet
	if client != nil {
		packet, _ = common.ParsePacket(incP.Data, client.Key)
	} else {
		packet, _ = common.ParsePacket(incP.Data, nil)
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
			server.WriteToUDP(common.NewKeyExchangePacket(serverPubKey.Bytes()).Bytes(), incP.Addr)
			sharedKey, err := serverPrivKey.ECDH(clientPubKey)

			clientVirtualIp := ipPool.Allocate()
			client := Client{
				Addr:      incP.Addr,
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
				incP.Addr,
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
				server.WriteToUDP(common.NewHeartbeatPacket().Bytes(), incP.Addr)
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
	cm.UpdateLastSeen(clientVirtIp)
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

func startWorkers[T any](n int, channel chan T, do func(t T)) {
	for i := 0; i < n; i++ {
		go func() {
			for val := range channel {
				do(val)
			}
		}()
	}
}
