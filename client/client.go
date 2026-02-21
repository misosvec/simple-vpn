package main

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
	"vpn/common"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunOffset       = 10
	mtu             = 1500
	tunIface        = "tun7"
	outboundWorkers = 4
	inboundWorkers  = 4
)

type Client struct {
	serverIp      string
	port          string
	logger        *slog.Logger
	conn          net.Conn
	tunDev        tun.Device
	privKey       *ecdh.PrivateKey
	sharedKey     []byte
	hostIP        netip.Prefix
	previousRoute []string

	outboundCh chan []byte
	inboundCh  chan common.Packet

	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewClient(serverIp string, port string, logger *slog.Logger) *Client {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &Client{
		serverIp:   serverIp,
		port:       port,
		logger:     logger,
		outboundCh: make(chan []byte, 1024),
		inboundCh:  make(chan common.Packet, 1024),
		ctx:        ctx,
		cancelFunc: cancelFunc,
	}
}

func (c *Client) Address() string {
	return c.serverIp + ":" + c.port
}

func StartWorkers[T any](n int, channel chan T, do func(t T)) {
	for range n {
		go func() {
			for val := range channel {
				do(val)
			}
		}()
	}
}

// Connect connects to the server, sets up the tun interface, and performs key
// exchange and virtual IP assignment synchronously. It returns once the client
// is ready to process traffic. Call Run() afterwards to start the traffic loop.
func (c *Client) Connect() error {
	conn, err := net.Dial("udp", c.Address())
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn
	fmt.Println("Connected to server")

	tunDev, err := common.SetupTunInterface(tunIface, mtu)
	if err != nil {
		return fmt.Errorf("failed to setup tun interface: %w", err)
	}
	c.tunDev = tunDev

	// small delay to propagate the tun interface to the kernel
	time.Sleep(100 * time.Millisecond)

	previousRoute, err := common.GetDefaultRoute()
	if err != nil {
		return fmt.Errorf("failed to get default route: %w", err)
	}
	c.previousRoute = previousRoute

	if err := common.SetDefaultRoute([]string{"default", "dev", tunIface}); err != nil {
		return fmt.Errorf("failed to set default route: %w", err)
	}

	if err := c.exchangeKeys(); err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	if err := c.receiveVirtualIP(); err != nil {
		return fmt.Errorf("virtual IP assignment failed: %w", err)
	}

	return nil
}

// Run starts the worker goroutines and blocks while processing traffic.
// It returns when the context is cancelled or a fatal error occurs.
func (c *Client) Run() error {
	StartWorkers(outboundWorkers, c.outboundCh, c.sendToServer)
	StartWorkers(inboundWorkers, c.inboundCh, c.handlePacket)
	go c.readTun()
	return c.readFromServer()
}

func (c *Client) Stop() {
	c.cancelFunc()
	c.tunDev.Close()
	c.conn.Close()

	if c.previousRoute != nil {
		common.SetDefaultRoute(c.previousRoute)
		c.previousRoute = nil
	}
}

func (c *Client) exchangeKeys() error {
	privKey, pubKey := common.GeneratePubPrivKeys()
	c.privKey = privKey

	if _, err := c.conn.Write(common.NewKeyExchangePacket(pubKey.Bytes()).Bytes()); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}

	buf := make([]byte, mtu)
	bytesRead, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read server key exchange: %w", err)
	}

	// Key-exchange packets are sent in plaintext, so parse without a shared key.
	packet, err := common.ParsePacket(buf[:bytesRead], nil)
	if err != nil {
		return fmt.Errorf("failed to parse server key exchange packet: %w", err)
	}

	kep, ok := packet.(common.KeyExchangePacket)
	if !ok {
		return fmt.Errorf("expected KeyExchangePacket, got %T", packet)
	}

	serverPubKey, err := ecdh.X25519().NewPublicKey(kep.Key())
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	c.sharedKey, err = c.privKey.ECDH(serverPubKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	c.logger.Debug("Shared key generated!")
	return nil
}

func (c *Client) receiveVirtualIP() error {
	buf := make([]byte, mtu)
	bytesRead, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read virtual IP packet: %w", err)
	}

	packet, err := common.ParsePacket(buf[:bytesRead], c.sharedKey)
	if err != nil {
		return fmt.Errorf("failed to parse virtual IP packet: %w", err)
	}

	vip, ok := packet.(common.VirtualIPPacket)
	if !ok {
		return fmt.Errorf("expected VirtualIPPacket, got %T", packet)
	}

	virtAddr, err := vip.VirtAddr()
	if err != nil {
		return fmt.Errorf("invalid virtual address: %w", err)
	}

	common.SetIpAddress(virtAddr.String(), tunIface)
	c.hostIP = virtAddr
	c.conn.Write(common.NewClientReadyPacket().Bytes())
	c.logger.Debug("VirtualIP set! Client ready!")
	return nil
}

func (c *Client) readTun() error {
	defer close(c.outboundCh)
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}
	sizes := make([]int, 16)

	for {
		packetsRead, err := c.tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tun read error: %w", err)
		}

		for i := range packetsRead {
			data := make([]byte, sizes[i])
			copy(data, bufs[i][tunOffset:tunOffset+sizes[i]])
			c.outboundCh <- data
		}
	}
}

// sendToServer encrypts and forwards a raw packet to the VPN server.
func (c *Client) sendToServer(data []byte) {
	packet := common.NewTrafficPacket(data)
	if !common.FilterPacket(packet, c.hostIP) {
		return
	}
	common.PrintParsedPacket(packet.Data())
	c.conn.Write(packet.BytesEncrypted(c.sharedKey))
}

func (c *Client) readFromServer() error {
	defer close(c.inboundCh)
	buf := make([]byte, mtu)
	fmt.Println("CLIENT: reading from server")

	for {
		bytesRead, err := c.conn.Read(buf)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("server read error: %w", err)
		}

		packet, err := common.ParsePacket(buf[:bytesRead], c.sharedKey)
		if err != nil {
			c.logger.Error("failed to parse packet", slog.String("error", err.Error()))
			continue
		}

		c.inboundCh <- packet
	}
}

func (c *Client) handlePacket(packet common.Packet) {
	var err error
	switch p := packet.(type) {
	case common.TrafficPacket:
		err = c.handleTraffic(p)
	case common.HeartbeatPacket:
		err = c.handleHeartbeat()
	}
	if err != nil {
		c.logger.Error("Failed to handle a packet", slog.String("error", err.Error()))
	}
}

func (c *Client) handleTraffic(p common.TrafficPacket) error {
	common.PrintParsedPacket(p.Bytes())
	tunBuf := make([]byte, tunOffset+p.DataLen())
	copy(tunBuf[tunOffset:], p.Data())
	_, err := c.tunDev.Write([][]byte{tunBuf}, tunOffset)
	return err
}

func (c *Client) handleHeartbeat() error {
	_, err := c.conn.Write(common.NewHeartbeatPacket().Bytes())
	c.logger.Debug("Client sent heartbeat answer!")
	return err
}

func main() {
	client := NewClient("vpn-server-cont", "8000", common.NewLogger(slog.LevelDebug))

	if err := client.Connect(); err != nil {
		panic(err)
	}

	defer client.Stop()

	if err := client.Run(); err != nil {
		panic(err)
	}
}
