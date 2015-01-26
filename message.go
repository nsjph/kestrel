package main

import (
	"log"
)

func newMessage(messageLength, paddingLength uint32) *Message {
	m := &Message{length: messageLength,
		padding:  paddingLength,
		payload:  make([]byte, messageLength+paddingLength),
		capacity: messageLength}

	log.Printf("newMessage->payload: %x", m.payload)
	return m

}

func messageShift(msg *Message, amount uint32) {

	if amount > 0 && msg.padding < amount {
		panic("Message shift - buffer overflow")
	} else if msg.length < (-amount) {
		panic("Message shift - buffer underflow")
	}

	// TODO: untested
	msg.length += amount
	msg.capacity += amount
	msg.payload = msg.payload[:-amount]
	msg.padding -= amount

}

func testMessage() *Message {
	payload := []byte("this is my test message")
	m := newMessage(23, 32)
	copy(m.payload[m.padding:], payload)

	log.Printf("message len %d, payload %x, padding %d, capacity %d", m.length, m.payload, m.padding, m.capacity)

	return m
}

func testMessage2() []byte {

	mymsg := []byte("        ")
	m := make([]byte, len(mymsg)+16)
	copy(m[16:], mymsg)

	return m

}
