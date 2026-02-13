package common

type MessageType byte

const (
	KeyExchangeMsg MessageType = 0x01
	VirtualIpMsg   MessageType = 0x02
	ClientReadyMsg MessageType = 0x03
	PacketMsg      MessageType = 0x04
	HeartbeatMsg   MessageType = 0x05
)

func GetMessageType(buf []byte) MessageType {
	return MessageType(buf[0])
}
