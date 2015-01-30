package main

import (
	_ "log"
)

const (
	CRYPTOAUTH_MESSAGE = 1
	SWITCH_MESSAGE     = 2

	CRYPTOAUTH_HANDSHAKE_MESSAGE = 0
	CRYPTOAUTH_DATA_MESSAGE      = 1

	CRYPTOAUTH_HANDSHAKE_NEW         = 0
	CRYPTOAUTH_HANDSHAKE_HELLO       = 1
	CRYPTOAUTH_HANDSHAKE_KEY_SYN     = 2 // Key "Send"
	CRYPTOAUTH_HANDSHAKE_KEY_ACK     = 3
	CRYPTOAUTH_HANDSHAKE_ESTABLISHED = 4
)

type MessageType interface {
	Protocol() int
}

type MessageBody interface {
	// Len returns the length of message body.
	Len() int
	// Marshal returns the binary enconding of message body.
	// Proto must be either cryptoauth.handshake or cryptoauth.data protocol number.
	Marshal(proto int) ([]byte, error)
}

// A DefaultMessageBody represents the default message body.
type DefaultMessageBody struct {
	Data []byte // data
}

// A Message represents an ICMP message.
type Message struct {
	Type     MessageType // type, either cryptoauth.handshake or cryptoauth.data
	Code     int         // code - state of the message, mainly for handshakes
	Checksum int         // checksum -- probably unecessary
	Body     MessageBody // body
}

func (p *DefaultMessageBody) Len() int {
	if p == nil {
		return 0
	}
	return len(p.Data)
}

// Marshal implements the Marshal method of MessageBody interface.
func (p *DefaultMessageBody) Marshal(proto int) ([]byte, error) {
	return p.Data, nil
}

// parseDefaultMessageBody parses b as an ICMP message body.
func parseDefaultMessageBody(proto int, b []byte) (MessageBody, error) {
	p := &DefaultMessageBody{Data: make([]byte, len(b))}
	copy(p.Data, b)
	return p, nil
}

func ParseMessage(proto int, b []byte) (*Message, error) {
	// if len(b) < 4 {
	// 	return nil, errMessageTooShort
	// }
	var err error
	m := &Message{Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3])}
	switch proto {
	case iana.ProtocolICMP:
		m.Type = ipv4.ICMPType(b[0])
	case iana.ProtocolIPv6ICMP:
		m.Type = ipv6.ICMPType(b[0])
	default:
		return nil, syscall.EINVAL
	}
	if fn, ok := parseFns[m.Type]; !ok {
		m.Body, err = parseDefaultMessageBody(proto, b[4:])
	} else {
		m.Body, err = fn(proto, b[4:])
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}
