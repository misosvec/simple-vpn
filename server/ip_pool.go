package main

import (
	"net/netip"
)

type IpPool struct {
	prefix    netip.Prefix
	allocated map[netip.Addr]struct{}
	next      netip.Addr
}

func NewPool(cidr string) *IpPool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic("TODO")
	}

	return &IpPool{
		prefix:    prefix,
		allocated: make(map[netip.Addr]struct{}),
		next:      prefix.Masked().Addr(),
	}
}

func (p *IpPool) Allocate() *netip.Addr {
	ip := p.next

	for {

		if !ip.IsValid() || !p.prefix.Contains(ip) {
			ip = p.prefix.Masked().Addr().Next()
		}

		if _, used := p.allocated[ip]; !used {
			p.allocated[ip] = struct{}{}
			p.next = ip.Next()
			return &ip
		}

		ip = ip.Next()
	}
}

func (p *IpPool) Release(ip netip.Addr) {
	if p.prefix.Contains(ip) {
		delete(p.allocated, ip)
	}
}
