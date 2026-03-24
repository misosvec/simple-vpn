package main

import (
	"net"
	"net/netip"
	"time"
	"vpn/common"
)

type Client struct {
	Addr      *net.UDPAddr
	Key       []byte
	VirtualIP netip.Addr
	LastSeen  time.Time
}

type ClientManager struct {
	clients *common.ConcurrentMap[netip.Addr, *Client]
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients: common.NewConcurrentMap[netip.Addr, *Client](),
	}
}

func (cm *ClientManager) AddClient(virtualIp netip.Addr, c *Client) {
	cm.clients.Store(virtualIp, c)
}

func (cm *ClientManager) GetClient(virtualIp netip.Addr) *Client {
	val, ok := cm.clients.Load(virtualIp)
	if !ok {
		return nil
	}
	return val
}

func (cm *ClientManager) RemoveClient(virtualIp netip.Addr) {
	if _, ok := cm.clients.Load(virtualIp); ok {
		cm.clients.Delete(virtualIp)
	}
}

func (cm *ClientManager) UpdateLastSeen(virtualIp netip.Addr) {
	if c, ok := cm.clients.Load(virtualIp); ok {
		c.LastSeen = time.Now()
	}
}
