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

// see cryptoauth.c ~245

// we use the first 32 bytes of the message payload for the encrypted nonce

// see cryptoauth.c ~ 579
// TODO: func encryptMessage

// Sending packets

// it would be nice to just use peer interface (peer *Peer)sendMessage, but we need to juggle where various keys are,
// so we use router interface instead
// need a memory-efficient way of keeping the router private keys and udpconn in each peer
func (router *Router) sendMessage(msg []byte, peer *Peer) {
	if peer.nextNonce < 4 {
		n, err := router.UDPConn.WriteToUDP(router.encryptHandshake(msg, peer), peer.addr)
		checkFatal(err)
		router.Log.Debug("wrote %d bytes to peer %s", n, peer.name)
	}
}

// GoPacket section below

// TODO: remove this - it's a temporary copy for experimenting with gopacket decoding

func (peer *Peer) receiveMessage(msg []byte) {
	if len(msg) < 20 {
		peer.log.Warning("receiveMessage(): packet too short, dropping")
		return
	}
}
