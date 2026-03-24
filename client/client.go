package main

import (
	"context"
	"crypto/ecdh"
	"errors"
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

	"golang.org/x/sync/errgroup"
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
	serverIp  string
	port      string
	logger    *slog.Logger
	conn      net.Conn
	connMu    sync.Mutex
	tunDev    tun.Device
	privKey   *ecdh.PrivateKey
	sharedKey []byte
	hostIP    netip.Prefix

	previousRoute []string

	// tunPacketCh carries raw IP packets read from the tun device.
	// They are unencrypted and not yet ready to send over the wire.
	tunPacketCh chan []byte

	// serverPacketCh carries packets received and parsed from the server conn.
	serverPacketCh chan common.Packet

	ctx        context.Context
	cancelFunc context.CancelFunc

	// stopOnce ensures Stop() is idempotent and safe to call concurrently.
	stopOnce   sync.Once
	lastActive time.Time
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

// StartWorkers launches n goroutines inside g that drain channel, calling do
// for each value. Only errors wrapped with fatal() are propagated to the
// errgroup (triggering shutdown). Non-fatal errors must be handled — logged
// and swallowed — by do itself. Each goroutine exits when the channel is
// closed and drained, or when the errgroup context is cancelled.
func StartWorkers[T any](g *errgroup.Group, ctx context.Context, n int, channel chan T, do func(T) error) {
	for range n {
		g.Go(func() error {
			for {
				select {
				case val, ok := <-channel:
					if !ok {
						return nil
					}
					if err := do(val); err != nil {
						var fe common.FatalErr
						if errors.As(err, &fe) {
							return err // bubble up → cancels errgroup → shutdown
						}
						// Non-fatal: do() is responsible for logging. Keep going.
					}
				case <-ctx.Done():
					return nil
				}
			}
		})
	}
}

// writeToConn serializes concurrent conn.Write calls via connMu.
// It is a no-op if the connection has already been closed.
func (c *Client) writeToConn(data []byte) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if _, err := c.conn.Write(data); err != nil {
		if !errors.Is(err, net.ErrClosed) && c.ctx.Err() == nil {
			c.logger.Error("failed to write to server", slog.Any("error", err))
			return nil
		}
		return err
	}
	c.lastActive = time.Now()
	return nil
}

// closeConn closes and nils c.conn under connMu, making writeToConn a safe
// no-op after this point. Idempotent.
func (c *Client) closeConn() {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Connect connects to the server, sets up the tun interface, and performs key
// exchange and virtual IP assignment synchronously. It returns once the client
// is ready to process traffic. Call Run() afterwards to start the traffic loop.
// On any failure after partial setup, Connect calls Stop() to clean up.
func (c *Client) Connect() error {
	conn, err := net.Dial("udp", c.Address())
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn
	c.logger.Info("connected to server", slog.String("addr", c.Address()))

	tunDev, err := common.SetupTunInterface(tunIface, mtu)
	if err != nil {
		c.Stop()
		return fmt.Errorf("failed to setup tun interface: %w", err)
	}
	c.tunDev = tunDev

	// Small delay to let the kernel propagate the new tun interface.
	time.Sleep(100 * time.Millisecond)

	previousRoute, err := common.GetDefaultRoute()
	if err != nil {
		c.Stop()
		return fmt.Errorf("failed to get default route: %w", err)
	}
	c.previousRoute = previousRoute

	if err := common.SetDefaultRoute([]string{"default", "dev", tunIface}); err != nil {
		c.Stop()
		return fmt.Errorf("failed to set default route: %w", err)
	}

	if err := c.exchangeKeys(); err != nil {
		c.Stop()
		return fmt.Errorf("key exchange failed: %w", err)
	}

	if err := c.receiveVirtualIP(); err != nil {
		c.Stop()
		return fmt.Errorf("virtual IP assignment failed: %w", err)
	}

	return nil
}

// Run starts the worker goroutines and blocks until all of them have finished.
// It returns the first fatal error from any goroutine, or nil on clean shutdown.
//
// Shutdown sequence:
//  1. A fatal error OR Stop() cancels the errgroup context (gCtx).
//  2. The context watcher calls Stop(), closing conn and tun device.
//  3. readTun and readFromServer unblock, detect cancellation, and return —
//     closing tunPacketCh and serverPacketCh respectively.
//  4. Worker goroutines drain their channels and exit.
//  5. g.Wait() unblocks and Run() returns.
func (c *Client) Run() error {
	g, gCtx := errgroup.WithContext(c.ctx)

	StartWorkers(g, gCtx, outboundWorkers, c.tunPacketCh, c.encryptAndSend)
	StartWorkers(g, gCtx, inboundWorkers, c.serverPacketCh, c.handlePacket)

	g.Go(func() error { return c.readTun() })
	g.Go(func() error { return c.readFromServer() })
	g.Go(func() error { return c.sendHeartbeat() })

	// When any goroutine fails (or Stop() is called externally), gCtx is
	// cancelled. We then call Stop() to close conn/tun and unblock any goroutines
	// still waiting on I/O. This watcher is intentionally outside g to avoid
	// a self-referential cancel cycle.
	go func() {
		<-gCtx.Done()
		c.Stop()
	}()

	err := g.Wait()
	// Context cancellation is the normal shutdown path — not an error for the caller.
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (c *Client) sendHeartbeat() error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(c.lastActive) >= 30*time.Second {
				if err := c.writeToConn(common.NewHeartbeatPacket().Bytes()); err != nil {
					return common.NewFatalError(fmt.Errorf("heartbeat write failed: %w", err))
				}
				c.logger.Debug("client sent heartbeat")
			}
		case <-c.ctx.Done():
			return nil
		}
	}
}

// Stop shuts the client down cleanly. Safe to call multiple times and from
// multiple goroutines concurrently.
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		// 1. Cancel the context first so goroutines can distinguish expected
		//    close errors from unexpected ones.
		c.cancelFunc()

		// 2. Close tun device — unblocks readTun.
		if c.tunDev != nil {
			c.tunDev.Close()
			c.tunDev = nil
		}

		// 3. Close the connection under connMu — unblocks readFromServer and
		//    makes subsequent writeToConn calls a safe no-op.
		c.closeConn()

		// 4. Restore the original default route.
		if c.previousRoute != nil {
			if err := common.SetDefaultRoute(c.previousRoute); err != nil {
				c.logger.Error("failed to restore default route", slog.Any("error", err))
			}
			c.previousRoute = nil
		}
	})
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

	c.logger.Debug("shared key generated")
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

	err = common.SetIpAddress(virtAddr.String(), tunIface)
	if err != nil {
		return fmt.Errorf("failed to set virtual IP address: %w", err)
	}
	c.hostIP = virtAddr

	if _, err := c.conn.Write(common.NewClientReadyPacket().Bytes()); err != nil {
		return fmt.Errorf("failed to send client ready: %w", err)
	}

	c.logger.Debug("virtual IP set, client ready")
	return nil
}

// readTun reads raw IP packets from the tun device and pushes them onto
// tunPacketCh. Any unexpected read error is returned as fatal.
func (c *Client) readTun() error {
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
				// expected shutdown
				return nil
			}
			return common.NewFatalError(fmt.Errorf("tun read failed: %w", err))
		}
		for i := range packetsRead {
			data := make([]byte, sizes[i])
			copy(data, bufs[i][tunOffset:tunOffset+sizes[i]])
			c.tunPacketCh <- data
		}
	}
}

// encryptAndSend encrypts a raw tun packet and writes it to the server conn.
// A failed write is non-fatal: the packet is dropped and logged, but the
// worker keeps running.
func (c *Client) encryptAndSend(data []byte) error {
	packet := common.NewTrafficPacket(data)
	if !common.FilterPacket(packet, c.hostIP) {
		return nil
	}
	common.PrintParsedPacket(packet.Data())
	c.writeToConn(packet.BytesEncrypted(c.sharedKey))
	// writeToConn handles its own logging; outbound packet loss is non-fatal.
	return nil
}

// readFromServer reads and parses packets from the server connection and pushes
// them onto serverPacketCh. A lost connection is fatal; a bad packet is not.
func (c *Client) readFromServer() error {
	defer close(c.serverPacketCh)
	buf := make([]byte, mtu)
	c.logger.Debug("reading from server")
	for {
		bytesRead, err := c.conn.Read(buf)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil // expected shutdown
			}
			return common.NewFatalError(fmt.Errorf("server read failure: %w", err))
		}
		packet, err := common.ParsePacket(buf[:bytesRead], c.sharedKey)
		if err != nil {
			// A single malformed packet is non-fatal — log and keep reading.
			c.logger.Error("failed to parse packet, skipping", slog.Any("error", err))
			continue
		}
		c.serverPacketCh <- packet
	}
}

// handlePacket dispatches a packet to the appropriate handler.
func (c *Client) handlePacket(packet common.Packet) error {
	switch p := packet.(type) {
	case common.TrafficPacket:
		return c.handleTraffic(p)
	}
	return nil
}

// handleTraffic writes a received traffic packet into the tun device.
// A tun write failure is fatal — the device is broken and the client
// cannot forward traffic anymore.
func (c *Client) handleTraffic(p common.TrafficPacket) error {
	tunBuf := make([]byte, tunOffset+p.DataLen())
	copy(tunBuf[tunOffset:], p.Data())
	if _, err := c.tunDev.Write([][]byte{tunBuf}, tunOffset); err != nil {
		// expected shutdown
		if c.ctx.Err() != nil {
			return nil
		}
		return common.NewFatalError(fmt.Errorf("tun write failure: %w", err))
	}
	return nil
}

func main() {
	logger := common.NewLogger(slog.LevelDebug)
	client := NewClient("vpn-server-cont", "8000", logger)

	if err := client.Connect(); err != nil {
		logger.Error("connect failed", slog.Any("error", err))
		os.Exit(1)
	}

	defer client.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
		client.Stop()
		// Do NOT call os.Exit here — let Run() return naturally so that
		// deferred cleanup in main() and any future callers also runs.
	}()

	if err := client.Run(); err != nil {
		logger.Error("run failed", slog.Any("error", err))
		os.Exit(1)
	}
}
