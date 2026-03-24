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
	"runtime"
	"sync"
	"time"
	"vpn/common"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	logger := common.NewLogger(slog.LevelDebug)
	client := NewClient("vpn-server-cont", "8000", logger)

	if err := client.Connect(); err != nil {
		logger.Error("connect failed", slog.Any("error", err))
		os.Exit(1)
	}

	defer client.Stop()

	if err := client.Run(); err != nil {
		logger.Error("run failed", slog.Any("error", err))
		os.Exit(1)
	}
}

const (
	tunOffset = 10
	mtu       = 1500
	tunIface  = "tun7"
)

type Client struct {
	serverIp         string
	port             string
	logger           *slog.Logger
	conn             net.Conn
	connMu           sync.Mutex
	tunDev           tun.Device
	privKey          *ecdh.PrivateKey
	sharedKey        []byte
	hostIP           netip.Prefix
	previousRoute    []string
	outboundPacketCh chan []byte
	inboundPacketsCh chan common.Packet
	ctx              context.Context
	cancelFunc       context.CancelFunc

	// stopOnce ensures Stop() is idempotent and safe to call concurrently.
	stopOnce   sync.Once
	lastActive time.Time

	tunBufPool sync.Pool
}

func NewClient(serverIp string, port string, logger *slog.Logger) *Client {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &Client{
		serverIp:         serverIp,
		port:             port,
		logger:           logger,
		outboundPacketCh: make(chan []byte, 1024),
		inboundPacketsCh: make(chan common.Packet, 1024),
		ctx:              ctx,
		cancelFunc:       cancelFunc,
		tunBufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, tunOffset+mtu)
				return &buf
			},
		},
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

	// small delay to let the kernel propagate the new tun interface.
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

	numCPU := runtime.GOMAXPROCS(0)

	// We split the workers: half for encryption/sending, half for receiving/decryption.
	// We ensure at least 1 worker even on single-core machines.
	workers := numCPU / 2
	if workers < 1 {
		workers = 1
	}

	StartWorkers(g, gCtx, workers, c.outboundPacketCh, c.encryptAndSend)
	StartWorkers(g, gCtx, workers, c.inboundPacketsCh, c.processInboundPacket)

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
	defer close(c.outboundPacketCh)
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, tunOffset+mtu)
	}
	sizes := make([]int, 16)
	for {
		packetsRead, err := c.tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return common.NewFatalError(fmt.Errorf("tun read failed: %w", err))
		}
		for i := range packetsRead {
			bufPtr := c.tunBufPool.Get().(*[]byte)
			data := (*bufPtr)[:sizes[i]]
			copy(data, bufs[i][tunOffset:tunOffset+sizes[i]])
			c.outboundPacketCh <- data
		}
	}
}

func (c *Client) encryptAndSend(data []byte) error {
	defer func() {
		// return buffer back to buffer pool
		full := data[:cap(data)]
		c.tunBufPool.Put(&full)
	}()

	packet := common.NewTrafficPacket(data)
	if !common.FilterPacket(packet, c.hostIP) {
		return nil
	}
	common.PrintParsedPacket(packet.Data())
	c.writeToConn(packet.BytesEncrypted(c.sharedKey))
	return nil
}

func (c *Client) readFromServer() error {
	defer close(c.inboundPacketsCh)
	buf := make([]byte, mtu)
	for {
		bytesRead, err := c.conn.Read(buf)

		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return common.NewFatalError(fmt.Errorf("server read failure: %w", err))
		}

		packet, err := common.ParsePacket(buf[:bytesRead], c.sharedKey)
		if err != nil {
			c.logger.Error("failed to parse packet, skipping", slog.Any("error", err))
			continue
		}
		c.inboundPacketsCh <- packet
	}
}

func (c *Client) processInboundPacket(packet common.Packet) error {
	switch p := packet.(type) {
	case common.TrafficPacket:
		bufPtr := c.tunBufPool.Get().(*[]byte)
		size := tunOffset + p.DataLen()
		buf := (*bufPtr)[:size]
		copy(buf[tunOffset:], p.Data())
		_, err := c.tunDev.Write([][]byte{buf}, tunOffset)
		c.tunBufPool.Put(bufPtr)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			return common.NewFatalError(fmt.Errorf("tun write failure: %w", err))
		}
	}
	return nil
}
