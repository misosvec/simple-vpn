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
	VirtualIP netip.Addr
	LastSeen  time.Time
}

func (c *Client) StartHeartbeat(ctx context.Context, sendHeartbeat func()) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(c.LastSeen) >= time.Duration(20*time.Second) {
				sendHeartbeat()
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

func (cm *ClientManager) AddClient(virtualIp netip.Addr, c *Client, sendHeartbeat func()) {
	ctx, cancel := context.WithCancel(context.Background())
	mc := &ManagedClient{
		Client: c,
		Cancel: cancel,
	}
	cm.clients.Store(virtualIp, mc)

	go c.StartHeartbeat(ctx, sendHeartbeat)
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
