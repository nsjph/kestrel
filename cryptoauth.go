// cryptoauth.go

package main

import (
	_ "bytes"
	_ "code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	_ "crypto/rand"
	_ "crypto/sha256"
	_ "encoding/binary"
	_ "encoding/hex"
	_ "golang.org/x/crypto/curve25519"
	_ "golang.org/x/crypto/nacl/box"
	_ "log"
	_ "math"
)

const (
	CryptoHeader_MAXLEN = 120
)

type CryptoAuthHeader struct {
	Nonce     uint32
	Handshake CryptoAuth_Handshake
	Payload   []byte
}

// type CryptoAuthHeader struct {
// }

type CryptoAuth_Handshake struct {
	Stage uint32
	//Challenge     CryptoAuth_Challenge
	Challenge     CryptoAuth_Challenge // We use a generic container initially then decode it into appropriate struct later
	Nonce         [24]byte             // 24 bytes
	PublicKey     [32]byte
	Authenticator [16]byte // 16 bytes
	TempPublicKey [32]byte // 32 bytes
	//Payload       []byte
}

type EncryptedHandshakeMessage struct {
	Handshake        *CryptoAuth_Handshake
	EncryptedPayload []byte
}

type EncryptedMessage struct {
	Nonce            uint32
	EncryptedPayload []byte
}

type CryptoAuth_Challenge struct {
	Type                                uint8
	Lookup                              [7]byte
	RequirePacketAuthAndDerivationCount uint16
	Additional                          uint16
}

// Alternative memory representation of CryptoAuth Challenge field
type CryptoAuth_Challenge_Bytes struct {
	bytes [12]uint8
}

// Alternative memory representation of CryptoAuth Challenge field
type CryptoAuth_Challenge_Ints struct {
	ints [3]uint32
}

func (peer *Peer) receiveMessage(msg []byte) {
	if len(msg) < 20 {
		peer.log.Warning("receiveMessage(): packet too short, dropping")
		return
	}
}
