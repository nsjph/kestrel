package main

import (
	_ "log"
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
