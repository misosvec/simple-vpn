package main

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
	connMu        sync.Mutex // guards all conn.Write calls
	tunDev        tun.Device
	privKey       *ecdh.PrivateKey
	sharedKey     []byte
	hostIP        netip.Prefix
	previousRoute []string
	// tunPacketCh carries raw IP packets read from the tun device.
	// They are unencrypted and not yet ready to send over the wire.
	tunPacketCh chan []byte
	// serverPacketCh carries packets received and parsed from the server conn.
	serverPacketCh chan common.Packet
	ctx            context.Context
	cancelFunc     context.CancelFunc
}

func NewClient(serverIp string, port string, logger *slog.Logger) *Client {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &Client{
		serverIp:       serverIp,
		port:           port,
		logger:         logger,
		tunPacketCh:    make(chan []byte, 1024),
		serverPacketCh: make(chan common.Packet, 1024),
		ctx:            ctx,
		cancelFunc:     cancelFunc,
	}
}

func (c *Client) Address() string {
	return c.serverIp + ":" + c.port
}

// StartWorkers launches n goroutines that drain channel, calling do for each
// value. Each goroutine calls wg.Done() when the channel is closed and drained.
func StartWorkers[T any](wg *sync.WaitGroup, n int, channel chan T, do func(t T)) {
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for val := range channel {
				do(val)
			}
		}()
	}
}

// writeToConn serializes concurrent conn.Write calls via a mutex.
func (c *Client) writeToConn(data []byte) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if _, err := c.conn.Write(data); err != nil {
		c.logger.Error("failed to write to server", slog.String("error", err.Error()))
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

// Run starts the worker goroutines and blocks until all of them have finished.
// Shutdown is triggered by Stop(), which closes the conn and tun device, causing
// the two reader goroutines (readTun, readFromServer) to return and close their
// respective channels. The workers drain those channels and exit, at which point
// Run() returns.
func (c *Client) Run() error {
	var wg sync.WaitGroup
	StartWorkers(&wg, outboundWorkers, c.tunPacketCh, c.encryptAndSend)
	StartWorkers(&wg, inboundWorkers, c.serverPacketCh, c.handlePacket)

	var readerWg sync.WaitGroup
	readerWg.Add(2)
	go func() {
		defer readerWg.Done()
		c.readTun()
	}()
	go func() {
		defer readerWg.Done()
		c.readFromServer()
	}()

	readerWg.Wait()
	wg.Wait()
	return nil
}

func (c *Client) Stop() {
	c.cancelFunc()
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

	if _, err := c.conn.Write(common.NewClientReadyPacket().Bytes()); err != nil {
		return fmt.Errorf("failed to send client ready: %w", err)
	}

	c.logger.Debug("VirtualIP set! Client ready!")
	return nil
}

func (c *Client) readTun() {
	defer close(c.tunPacketCh)
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}
	sizes := make([]int, 16)
	for {
		packetsRead, err := c.tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.logger.Error("tun read error", slog.String("error", err.Error()))
			return
		}
		for i := range packetsRead {
			data := make([]byte, sizes[i])
			copy(data, bufs[i][tunOffset:tunOffset+sizes[i]])
			c.tunPacketCh <- data
		}
	}
}

// encryptAndSend encrypts a raw tun packet and writes it to the server conn.
func (c *Client) encryptAndSend(data []byte) {
	packet := common.NewTrafficPacket(data)
	if !common.FilterPacket(packet, c.hostIP) {
		return
	}
	common.PrintParsedPacket(packet.Data())
	c.writeToConn(packet.BytesEncrypted(c.sharedKey))
}

func (c *Client) readFromServer() {
	defer close(c.serverPacketCh)
	buf := make([]byte, mtu)
	fmt.Println("CLIENT: reading from server")
	for {
		bytesRead, err := c.conn.Read(buf)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.logger.Error("server read error", slog.String("error", err.Error()))
			return
		}
		packet, err := common.ParsePacket(buf[:bytesRead], c.sharedKey)
		if err != nil {
			c.logger.Error("failed to parse packet", slog.String("error", err.Error()))
			continue
		}
		c.serverPacketCh <- packet
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
	c.writeToConn(common.NewHeartbeatPacket().Bytes())
	c.logger.Debug("Client sent heartbeat answer!")
	return nil
}

func main() {
	client := NewClient("vpn-server-cont", "8000", common.NewLogger(slog.LevelDebug))
	if err := client.Connect(); err != nil {
		panic(err)
	}
	defer client.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("Received shutdown signal")
		client.Stop()
		os.Exit(0) // Optional: ensure prompt exit after Stop()
	}()

	if err := client.Run(); err != nil {
		panic(err)
	}
}
