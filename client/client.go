package main

import (
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
}

func NewClient(serverIp string, port string, logger *slog.Logger) *Client {
	return &Client{
		serverIp:   serverIp,
		port:       port,
		logger:     logger,
		outboundCh: make(chan []byte, 1024),
		inboundCh:  make(chan common.Packet, 1024),
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

// Start connects to the server, sets up the tun interface, and performs key
// exchange synchronously before starting any other traffic. It returns quickly;
// call Run() to begin processing traffic.
func (c *Client) Start() error {
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

	// Perform key exchange synchronously before starting workers or reading
	// from the server, so that c.sharedKey is always set before any packet
	// decryption takes place.
	if err := c.exchangeKeys(); err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	StartWorkers(outboundWorkers, c.outboundCh, c.sendToServer)
	StartWorkers(inboundWorkers, c.inboundCh, c.handlePacket)
	c.readFromServer()
	return nil
}

// Stop closes all resources and restores the previous network state.
func (c *Client) Stop() {
	if c.tunDev != nil {
		c.tunDev.Close()
		c.tunDev = nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	if c.previousRoute != nil {
		common.SetDefaultRoute(c.previousRoute)
		c.previousRoute = nil
	}
	close(c.inboundCh)
	close(c.outboundCh)
}

// exchangeKeys sends our public key, then synchronously waits for the server's
// public key reply and derives the shared secret before returning.
func (c *Client) exchangeKeys() error {
	privKey, pubKey := common.GeneratePubPrivKeys()
	c.privKey = privKey

	if _, err := c.conn.Write(common.NewKeyExchangePacket(pubKey.Bytes()).Bytes()); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}

	// Read exactly one packet — the server's KeyExchangePacket.
	buf := make([]byte, mtu)
	bytesRead, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read server key exchange: %w", err)
	}

	// At this point c.sharedKey is not yet set, so we parse without decryption
	// (key-exchange packets are sent in plaintext).
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

// readTun reads raw packets from the tun device and fans them out to outboundCh.
func (c *Client) readTun() {
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}
	sizes := make([]int, 16)

	for {
		packetsRead, err := c.tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			panic(fmt.Errorf("tun read error: %w", err))
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

// readFromServer reads from the server connection and fans packets out to inboundCh.
func (c *Client) readFromServer() {
	buf := make([]byte, mtu)
	fmt.Println("CLIENT: reading from server")

	for {
		bytesRead, err := c.conn.Read(buf)
		if err != nil {
			panic(fmt.Errorf("server read error: %w", err))
		}

		packet, err := common.ParsePacket(buf[:bytesRead], c.sharedKey)
		if err != nil {
			panic(fmt.Errorf("packet parse error: %w", err))
		}

		c.inboundCh <- packet
	}
}

// handlePacket dispatches a parsed packet to the appropriate handler.
func (c *Client) handlePacket(packet common.Packet) {
	var err error
	switch p := packet.(type) {
	case common.KeyExchangePacket:
		err = c.handleKeyExchange(p)
	case common.VirtualIPPacket:
		err = c.handleVirtualIP(p)
	case common.TrafficPacket:
		err = c.handleTraffic(p)
	case common.HeartbeatPacket:
		err = c.handleHeartbeat()
	}
	if err != nil {
		panic(err)
	}
}

// handleKeyExchange is kept for completeness but should no longer be reached
// during normal operation since key exchange is now done synchronously in
// exchangeKeys().
func (c *Client) handleKeyExchange(p common.KeyExchangePacket) error {
	serverPubKey, err := ecdh.X25519().NewPublicKey(p.Key())
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

func (c *Client) handleVirtualIP(p common.VirtualIPPacket) error {
	virtAddr, err := p.VirtAddr()
	if err != nil {
		return fmt.Errorf("invalid virtual address: %w", err)
	}
	common.SetIpAddress(virtAddr.String(), tunIface)
	c.conn.Write(common.NewClientReadyPacket().Bytes())
	c.logger.Debug("VirtualIP set! Client ready!")
	go c.readTun()
	return nil
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

	if err := client.Start(); err != nil {
		panic(err)
	}
	defer client.Stop()
}
