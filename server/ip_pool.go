package main

import (
	"net/netip"
	"vpn/common"
)

type IpPool struct {
	prefix    netip.Prefix
	allocated *common.ConcurrentMap[netip.Addr, struct{}]
	next      netip.Addr
}

func NewIpPool(cidr string) *IpPool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic("TODO")
	}

	return &IpPool{
		prefix:    prefix,
		allocated: common.NewConcurrentMap[netip.Addr, struct{}](),
		next:      prefix.Masked().Addr().Next(),
	}
}

func (p *IpPool) Allocate() netip.Addr {
	ip := p.next

	for {

		if !ip.IsValid() || !p.prefix.Contains(ip) {
			ip = p.prefix.Masked().Addr().Next()
		}

		// TODO check for network and broadcast IP

		if _, used := p.allocated.Load(ip); !used {
			p.allocated.Store(ip, struct{}{})
			p.next = ip.Next()
			return ip
		}

		ip = ip.Next()
	}
}

func (p *IpPool) Release(ip netip.Addr) {
	if p.prefix.Contains(ip) {
		p.allocated.Delete(ip)
	}
}
