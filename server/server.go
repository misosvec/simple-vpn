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
	"strconv"
	"sync"
	"syscall"
	"time"
	"vpn/common"

	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunOffset       = 10
	tunIface        = "tun8"
	mtu             = 1500
	listenAddr      = "0.0.0.0:8000"
	inboundWorkers  = 3
	outboundWorkers = 3
)

// Server holds all state for the VPN server.
type Server struct {
	logger *slog.Logger

	conn   *net.UDPConn
	connMu sync.Mutex

	tunDev tun.Device

	ipPool         *IpPool
	cm             *ClientManager
	pendingClients *common.ConcurrentMap[string, *Client]
	realToVirtual  *common.ConcurrentMap[string, netip.Addr]

	// inboundCh carries packets arriving from VPN clients.
	inboundCh chan common.IncomingPacket

	// outboundCh carries IP packets that the TUN device produced and need
	// to be forwarded to the appropriate VPN client.
	outboundCh chan common.Packet

	ctx        context.Context
	cancelFunc context.CancelFunc
	stopOnce   sync.Once
}

func NewServer(logger *slog.Logger, cidr string) *Server {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &Server{
		logger:         logger,
		ipPool:         NewIpPool(cidr),
		cm:             NewClientManager(),
		pendingClients: common.NewConcurrentMap[string, *Client](),
		realToVirtual:  common.NewConcurrentMap[string, netip.Addr](),
		inboundCh:      make(chan common.IncomingPacket, 2048),
		outboundCh:     make(chan common.Packet, 2048),
		ctx:            ctx,
		cancelFunc:     cancelFunc,
	}
}

// Listen binds the UDP socket and sets up the TUN interface. It must be called
// before Run(). On any failure, Listen cleans up partial state via Stop().
func (s *Server) Listen() error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	s.conn = conn
	s.logger.Info("listening on UDP", slog.String("addr", listenAddr))

	tunDev, err := common.SetupTunInterface(tunIface, mtu)
	if err != nil {
		s.Stop()
		return fmt.Errorf("failed to setup tun interface: %w", err)
	}
	s.tunDev = tunDev

	serverIP := s.ipPool.Allocate()
	serverAddr := fmt.Sprintf("%s/%d", serverIP, s.ipPool.prefix.Bits())
	if err := common.SetIpAddress(serverAddr, tunIface); err != nil {
		s.Stop()
		return fmt.Errorf("failed to set tun IP: %w", err)
	}

	if err := common.EnablePostrouting(s.ipPool.prefix.Masked().String()); err != nil {
		s.Stop()
		return fmt.Errorf("failed to enable postrouting: %w", err)
	}

	return nil
}

// Run starts all worker goroutines and blocks until they have all finished.
// It returns the first fatal error, or nil on clean shutdown.
func (s *Server) Run() error {
	g, gCtx := errgroup.WithContext(s.ctx)

	startWorkers(g, gCtx, inboundWorkers, s.inboundCh, s.processClientPacket)
	startWorkers(g, gCtx, outboundWorkers, s.outboundCh, s.sendPacketToClient)

	g.Go(func() error { return s.readFromClients() })
	g.Go(func() error { return s.readTun() })

	go func() {
		<-gCtx.Done()
		s.Stop()
	}()

	err := g.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// Stop shuts the server down cleanly. Safe to call multiple times and from
// multiple goroutines concurrently.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		s.cancelFunc()

		if s.tunDev != nil {
			s.tunDev.Close()
			s.tunDev = nil
			common.DeleteInterface(tunIface)
			s.logger.Info("tun interface destroyed")
		}

		s.connMu.Lock()
		if s.conn != nil {
			s.conn.Close()
			s.conn = nil
		}
		s.connMu.Unlock()
	})
}

// writeToUDP serializes concurrent writes via connMu.
func (s *Server) writeToUDP(data []byte, addr *net.UDPAddr) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conn == nil {
		return
	}
	if _, err := s.conn.WriteToUDP(data, addr); err != nil {
		if !errors.Is(err, net.ErrClosed) && s.ctx.Err() == nil {
			s.logger.Error("failed to write to client", slog.Any("error", err), slog.String("addr", addr.String()))
		}
	}
}

// readFromClients reads UDP datagrams and pushes them onto inboundCh.
// A read error while the server is shutting down is treated as clean exit;
// otherwise it is fatal.
func (s *Server) readFromClients() error {
	defer close(s.inboundCh)
	buf := make([]byte, mtu)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return common.NewFatalError(fmt.Errorf("UDP read failure: %w", err))
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		s.inboundCh <- common.IncomingPacket{Data: data, Addr: addr}
	}
}

// readTun reads IP packets from the TUN device and pushes them onto outboundCh.
func (s *Server) readTun() error {
	defer close(s.outboundCh)
	bufs := make([][]byte, 16)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}
	sizes := make([]int, 16)

	for {
		packetsRead, err := s.tunDev.Read(bufs, sizes, tunOffset)
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return common.NewFatalError(fmt.Errorf("tun read failure: %w", err))
		}
		for i := range packetsRead {
			packet := common.NewTrafficPacket(bufs[i][tunOffset : tunOffset+sizes[i]])
			if !common.FilterPacket(packet, s.ipPool.prefix) {
				continue
			}
			s.outboundCh <- packet
		}
	}
}

// processClientPacket handles a single inbound packet from a VPN client.
// Non-fatal errors are logged and swallowed so the worker keeps running.
func (s *Server) processClientPacket(incP common.IncomingPacket) error {
	clientKey := incP.Addr.IP.String() + ":" + strconv.Itoa(incP.Addr.Port)

	clientVirtIP, known := s.realToVirtual.Load(clientKey)

	var client *Client
	if known {
		client = s.cm.GetClient(clientVirtIP)
	}

	var key []byte
	if client != nil {
		key = client.Key
	}

	packet, err := common.ParsePacket(incP.Data, key)
	if err != nil {
		s.logger.Error("failed to parse client packet, skipping",
			slog.String("clientKey", clientKey), slog.Any("error", err))
		return nil
	}

	switch p := packet.(type) {
	case common.KeyExchangePacket:
		s.handleKeyExchange(clientKey, incP.Addr, p)

	case common.ClientReadyPacket:
		s.handleClientReady(clientKey, incP.Addr)
	case common.TrafficPacket:
		s.handleTraffic(clientKey, p)
	case common.HeartbeatPacket:{
		s.logger.Debug("heartbeat received", slog.String("clientKey", clientKey))
	}
	default:
		s.logger.Debug("unknown packet type", slog.String("clientKey", clientKey))
	}

	if known {
		s.cm.UpdateLastSeen(clientVirtIP)
	}
	return nil
}

func (s *Server) handleKeyExchange(clientKey string, addr *net.UDPAddr, p common.KeyExchangePacket) {
	s.logger.Info("key exchange received", slog.String("clientKey", clientKey))

	clientPubKey, err := ecdh.X25519().NewPublicKey(p.Key())
	if err != nil {
		s.logger.Error("invalid client public key", slog.Any("error", err))
		return
	}

	serverPrivKey, serverPubKey := common.GeneratePubPrivKeys()
	s.writeToUDP(common.NewKeyExchangePacket(serverPubKey.Bytes()).Bytes(), addr)

	sharedKey, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		s.logger.Error("ECDH failed", slog.Any("error", err))
		return
	}

	virtualIP := s.ipPool.Allocate()
	client := &Client{
		Addr:      addr,
		Key:       sharedKey,
		LastSeen:  time.Now(),
		VirtualIP: virtualIP,
	}

	s.realToVirtual.Store(clientKey, virtualIP)
	s.pendingClients.Store(clientKey, client)

	s.writeToUDP(
		common.NewVirtualIpPacket(
			virtualIP.AsSlice(),
			[]byte{byte(s.ipPool.prefix.Bits())},
		).BytesEncrypted(sharedKey),
		addr,
	)
	s.logger.Debug("virtual IP assigned", slog.String("virtualIP", virtualIP.String()))
}

func (s *Server) handleClientReady(clientKey string, addr *net.UDPAddr) {
	virtualIP, ok := s.realToVirtual.Load(clientKey)
	if !ok {
		s.logger.Warn("ClientReady: no virtual IP mapping", slog.String("clientKey", clientKey))
		return
	}

	pendingClient, ok := s.pendingClients.Load(clientKey)
	if !ok {
		s.logger.Warn("ClientReady: no pending client", slog.String("clientKey", clientKey))
		return
	}

	s.cm.AddClient(virtualIP, pendingClient)
	s.pendingClients.Delete(clientKey)
	s.logger.Info("client ready", slog.String("clientKey", clientKey))
}

func (s *Server) handleTraffic(clientKey string, p common.TrafficPacket) {
	payload := make([]byte, tunOffset+p.DataLen())
	copy(payload[tunOffset:], p.Data())

	_, err := s.tunDev.Write([][]byte{payload}, tunOffset)
	if err != nil {
		if s.ctx.Err() != nil {
			return
		}
		s.logger.Error("tun write failed", slog.String("clientKey", clientKey), slog.Any("error", err))
		return
	}
	s.logger.Debug("packet written to tun", slog.String("clientKey", clientKey))
}

// sendPacketToClient encrypts an IP packet from the TUN device and forwards it
// to the appropriate VPN client. A missing client is non-fatal (the client may
// have disconnected); a write error is also non-fatal.
func (s *Server) sendPacketToClient(p common.Packet) error {
	destIP := p.GetDestAddr()
	client := s.cm.GetClient(destIP)
	if client == nil {
		s.logger.Warn("no client for destination IP", slog.String("destIP", destIP.String()))
		return nil
	}
	s.writeToUDP(p.BytesEncrypted(client.Key), client.Addr)
	s.logger.Debug("packet forwarded to client", slog.String("clientAddr", client.Addr.String()))
	return nil
}

// startWorkers launches n goroutines inside g that drain ch, calling do for
// each value. Fatal errors propagate; non-fatal ones must be handled by do.
func startWorkers[T any](g *errgroup.Group, ctx context.Context, n int, ch chan T, do func(T) error) {
	for range n {
		g.Go(func() error {
			for {
				select {
				case val, ok := <-ch:
					if !ok {
						return nil
					}
					if err := do(val); err != nil {
						var fe common.FatalErr
						if errors.As(err, &fe) {
							return err
						}
					}
				case <-ctx.Done():
					return nil
				}
			}
		})
	}
}

func main() {
	logger := common.NewLogger(slog.LevelDebug)
	server := NewServer(logger, "12.0.0.1/24")

	if err := server.Listen(); err != nil {
		logger.Error("listen failed", slog.Any("error", err))
		os.Exit(1)
	}
	defer server.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
		server.Stop()
	}()

	if err := server.Run(); err != nil {
		logger.Error("run failed", slog.Any("error", err))
		os.Exit(1)
	}
}
