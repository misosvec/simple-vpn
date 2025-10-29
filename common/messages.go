package common

type MessageType byte

const (
	KeyExchangeMsg MessageType = 0x01
	PacketMsg      MessageType = 0x02
)
