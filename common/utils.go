package common

func CreateMessage(mt MessageType, nonce []byte, content []byte) []byte {
	msg := append([]byte{byte(mt)}, nonce...)
	msg = append(msg, content...)
	return msg
}
