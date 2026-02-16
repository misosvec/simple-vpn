package common

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

const (
	nonceLength = 12
	keyLength   = 32
)

type PacketType byte

const (
	TypeKeyExchange PacketType = 1
	TypeVirtualIP   PacketType = 2
	TypeClientReady PacketType = 3
	TypeHeartbeat   PacketType = 4
	TypeTraffic     PacketType = 5
)

type IncomingPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

type PacketBase struct {
	pt   PacketType
	data []byte
}

func NewPacketBase(pt PacketType, data ...[]byte) PacketBase {
	content := []byte{}

	for _, d := range data {
		content = append(content, d...)
	}

	return PacketBase{pt, content}
}

func (p PacketBase) Data() []byte {
	return p.data
}

func (p PacketBase) DataLen() int {
	return len(p.data)
}
func (p PacketBase) Type() PacketType {
	return p.pt
}
func (p PacketBase) Bytes() []byte {
	return append([]byte{byte(p.pt)}, p.data...)
}

func (p PacketBase) BytesEncrypted(key []byte) []byte {
	nonce, encrypted := Encrypt(p.data, key)
	return NewPacketBase(p.pt, nonce, encrypted).Bytes()
}

func (p PacketBase) GetDestAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(p.data[16:20])
	return ip
}

func (p PacketBase) GetIpVersion() int {
	return int(p.data[0] >> 4)
}

// Packet interface
type Packet interface {
	Type() PacketType
	Data() []byte
	DataLen() int
	GetDestAddr() netip.Addr
	GetIpVersion() int
	BytesEncrypted(key []byte) []byte
	Bytes() []byte
}

type TrafficPacket struct {
	PacketBase
}

func NewTrafficPacket(data []byte) TrafficPacket {
	return TrafficPacket{
		NewPacketBase(TypeTraffic, data),
	}
}

type KeyExchangePacket struct {
	PacketBase
}

func NewKeyExchangePacket(data []byte) KeyExchangePacket {
	return KeyExchangePacket{
		NewPacketBase(TypeKeyExchange, data),
	}
}

func (p KeyExchangePacket) Key() []byte {
	return p.data[0:keyLength]
}

type VirtualIPPacket struct {
	PacketBase
}

func NewVirtualIpPacket(data ...[]byte) VirtualIPPacket {
	return VirtualIPPacket{NewPacketBase(TypeVirtualIP, data...)}
}

func (p VirtualIPPacket) VirtAddr() (netip.Prefix, error) {
	ip, ok := netip.AddrFromSlice(p.Data()[0:4])
	if !ok {
		return netip.Prefix{}, errors.New("Failed to parse IP address!")
	}
	return netip.PrefixFrom(ip, int(p.Data()[4])), nil
}

type ClientReadyPacket struct {
	PacketBase
}

func NewClientReadyPacket() ClientReadyPacket {
	return ClientReadyPacket{NewPacketBase(TypeClientReady)}
}

type HeartbeatPacket struct {
	PacketBase
}

func NewHeartbeatPacket() HeartbeatPacket {
	return HeartbeatPacket{NewPacketBase(TypeHeartbeat)}
}

// Helper function to determine if a packet type is encrypted
func isEncrypted(pt PacketType) bool {
	switch pt {
	case TypeTraffic, TypeVirtualIP:
		return true
	default:
		return false
	}
}

// ParsePacket parses a raw byte buffer into a specific packet type
func ParsePacket(buf []byte, key []byte) (Packet, error) {
	if len(buf) < 1 {
		return nil, errors.New("packet too short")
	}
	pt := PacketType(buf[0])

	data := buf[1:]
	var finalPayload []byte

	// 2. Handle Encryption / Decryption
	if isEncrypted(pt) {
		if len(data) < nonceLength {
			return nil, errors.New("data too short for nonce")
		}
		nonce := data[:nonceLength]
		ciphertext := data[nonceLength:]

		decrypted, err := Decrypt(nonce, ciphertext, key)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
		finalPayload = decrypted
	} else {
		finalPayload = data
	}

	// 3. Create specific packet type with embedded PacketBase
	switch pt {
	case TypeTraffic:
		return TrafficPacket{PacketBase{pt, finalPayload}}, nil
	case TypeKeyExchange:
		return KeyExchangePacket{PacketBase{pt, finalPayload}}, nil
	case TypeVirtualIP:
		return VirtualIPPacket{PacketBase{pt, finalPayload}}, nil
	case TypeClientReady:
		return ClientReadyPacket{PacketBase{pt, finalPayload}}, nil
	case TypeHeartbeat:
		return HeartbeatPacket{PacketBase{pt, finalPayload}}, nil
	default:
		return nil, fmt.Errorf("unknown packet type: %d", pt)
	}
}

func FilterPacket(packet Packet, prefix netip.Prefix) bool {

	version := packet.GetIpVersion()
	if version != 4 {
		return false
	}

	destAddr := packet.GetDestAddr()

	if isSubnetBroadcast(destAddr, prefix) {
		return false
	}

	if destAddr.IsMulticast() {
		return false
	}

	if destAddr.IsLoopback() {
		return false
	}

	return true
}

func isSubnetBroadcast(addr netip.Addr, prefix netip.Prefix) bool {
	if !prefix.Contains(addr) {
		return false
	}

	// Get network address
	network := prefix.Masked().Addr()

	// Calculate broadcast
	bits := prefix.Bits()
	hostBits := 32 - bits

	// Convert to uint32
	ip := network.As4()
	ipInt := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])

	broadcastInt := ipInt | (1<<hostBits - 1)

	broadcast := netip.AddrFrom4([4]byte{
		byte(broadcastInt >> 24),
		byte(broadcastInt >> 16),
		byte(broadcastInt >> 8),
		byte(broadcastInt),
	})

	return addr == broadcast
}
