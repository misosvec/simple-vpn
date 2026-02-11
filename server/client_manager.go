package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Client struct {
	Addr      *net.UDPAddr
	Key       []byte
	VirtualIP *netip.Addr
	LastSeen  time.Time
}

func (c *Client) sendHeartbeat(conn *net.UDPConn) {
	conn.WriteToUDP([]byte("HB"), c.Addr)
	fmt.Printf("Sent heartbeat to %s\n", c.Addr.String())
}

func (c *Client) startHeartbeat(ctx context.Context, conn *net.UDPConn) {
	ticker := time.NewTicker(time.Duration(time.Duration.Seconds(20)))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(c.LastSeen) >= time.Duration(time.Duration.Seconds(20)) {
				c.sendHeartbeat(conn)
			}
		case <-ctx.Done():
			fmt.Printf("Stopping heartbeat for %s\n", c.Addr.String())
			return
		}
	}
}

type ManagedClient struct {
	Client *Client
	Cancel context.CancelFunc
}

type ClientManager struct {
	clients sync.Map
}

func (cm *ClientManager) AddClient(virtualIp netip.Addr, c *Client, conn *net.UDPConn) {
	ctx, cancel := context.WithCancel(context.Background())
	mc := &ManagedClient{
		Client: c,
		Cancel: cancel,
	}
	cm.clients.Store(virtualIp, mc)

	go c.startHeartbeat(ctx, conn)
}

func (cm *ClientManager) GetClient(virtualIp netip.Addr) *Client {
	val, ok := cm.clients.Load(virtualIp)
	if !ok {
		return nil
	}
	return val.(*ManagedClient).Client
}

func (cm *ClientManager) RemoveClient(virtualIp netip.Addr) {
	if val, ok := cm.clients.Load(virtualIp); ok {
		mc := val.(*ManagedClient)
		mc.Cancel()
		cm.clients.Delete(virtualIp)
	}
}

func (cm *ClientManager) UpdateLastSeen(virtualIp netip.Addr) {
	if val, ok := cm.clients.Load(virtualIp); ok {
		mc := val.(*ManagedClient)
		mc.Client.LastSeen = time.Now()
	}
}
