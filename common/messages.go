package common

type MessageType byte

const (
	KeyExchangeMsg MessageType = 0x01
	PacketMsg      MessageType = 0x02
	HeartbeatMsg   MessageType = 0x03
)

func GetMessageType(buf []byte) MessageType {
	return MessageType(buf[0])
}
