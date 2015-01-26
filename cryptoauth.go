// cryptoauth.go

package main

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	_ "encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"log"
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

func encryptRandomNonce(nonce [24]byte, msg []byte, secret [32]byte) ([]byte, []byte) {
	// if msg.padding < 32 {
	// 	panic("padding too small")
	// }

	// startAt := make([]byte, len(msg))
	// copy(startAt, msg[16:])
	// log.Printf("startat(%d): %x", len(startAt), startAt)
	// //copy(startAt, msg.payload[:msg.length+msg.padding-32])
	// //authenticator := make([]byte, 16)
	// //encryptedOut = make([]byte, msg.length+16)
	// //auth2 := make([]byte, 16)
	// //log.Printf("msg payload: %x", msg.payload)
	// log.Printf("nonce: %x, secret %x", nonce, secret)
	log.Printf("msg len %d", len(msg))
	//z := make([]byte, len(msg))

	encryptedMsg := box.SealAfterPrecomputation(msg, msg, &nonce, &secret)
	// log.Printf("msg after: %x", msg)
	// log.Printf("encryptedmsg %x", encryptedMsg)
	// log.Printf("length of encryptedmsg: %d", len(encryptedMsg))

	return encryptedMsg, msg
}

func (router *Router) getSharedSecret(peer *Peer) {
	if peer.password == nil {
		log.Printf("getsharedsecret remote peer public key in b32: %s\n", base32Encode(peer.publicKey[:])[:52])
		box.Precompute(&peer.sharedKey, &peer.publicKey, &router.PrivateKey)
	} else {
		panic("write this part of getSharedSecret")
	}
}

func (router *Router) encryptHandshake(msg []byte, peer *Peer) []byte {
	h := &CryptoAuth_Handshake{}

	h.Stage = peer.nextNonce + 1
	//n, err := rand.Read(h.Challenge) // TODO: does this fill the entirety?
	//log.Println("random bytes read into h.Challenge:", n)
	h.Challenge.Type = 0
	z := make([]byte, 7)
	rand.Read(z)
	copy(h.Challenge.Lookup[:], z)
	//rand.Read(h.Challenge.Lookup)
	h.Challenge.RequirePacketAuthAndDerivationCount = 1
	h.Challenge.Additional = 1
	h.PublicKey = router.PublicKey
	n, err := rand.Read(h.Nonce[:])
	checkFatal(err)
	log.Println("random bytes read into h.Nonce", n)

	if peer.nextNonce == 0 || peer.nextNonce == 2 {
		// Generate temp keypair
		peer.tempPublicKey, peer.tempPrivateKey = createTempKeyPair()
		h.TempPublicKey = peer.tempPublicKey
	}

	if peer.nextNonce < 2 {
		// Generate shared secret
		router.getSharedSecret(peer)
	} else {
		// see cryptoauth.c ~534

		panic("write this part of encryptHandshake")
	}

	// write out into bigendian once we have fully constructed the header
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, h.Stage)
	err = binary.Write(buf, binary.BigEndian, h.Challenge.Type)
	err = binary.Write(buf, binary.BigEndian, h.Challenge.Lookup)
	err = binary.Write(buf, binary.BigEndian, h.Challenge.RequirePacketAuthAndDerivationCount)
	err = binary.Write(buf, binary.BigEndian, h.Challenge.Additional)
	err = binary.Write(buf, binary.BigEndian, h.Nonce)
	err = binary.Write(buf, binary.BigEndian, h.PublicKey)

	router.Log.Debug("sending message with:\n\tnonce: %x\n\tsecret: %x\n\t", h.Nonce, peer.sharedKey)

	//log.Printf("cryptoauth len: %d", len(buf.Bytes()))
	y := make([]byte, 72)
	copy(y[:len(buf.Bytes())], buf.Bytes())
	//log.Printf("msg before: %x", y)

	encryptedMsg, authenticator := encryptRandomNonce(h.Nonce, y, peer.sharedKey)
	copy(h.Authenticator[:], authenticator)
	//log.Println(len(encryptedMsg))
	//h.Payload = encryptedMsg

	//ehm := &EncryptedHandshakeMessage{Handshake: h, EncryptedPayload: encryptedMsg}

	// This is where we need to construct the final message packet with cryptoauth + appended msg payload?

	//err = binary.Write(buf, binary.BigEndian, encryptedMsg)

	router.Peers[peer.name] = peer

	// debug using gopacket

	p := gopacket.NewPacket(buf.Bytes(), LayerTypeHandshake, gopacket.Lazy)

	var h2 *Handshake

	if handshakeLayer := p.Layer(LayerTypeHandshake); handshakeLayer != nil {
		router.Log.Debug("XXX This is a handshake packet!")
		h2, _ = handshakeLayer.(*Handshake)
		router.Log.Debug("handshake stage: %d", h2.Stage)

		//router.Log.Debug("outbound packet: %s", p.String())

		// for _, layer := range p.Layers() {
		// 	log.Println("PACKET LAYER:", layer.LayerType)
		// }
		//router.Log.Debug(p.LayerDump(gopacket.ApplicationLayer))
	}

	return encryptedMsg
}

// see cryptoauth.c ~ 579
// TODO: func encryptMessage

func (c *CryptoAuth_Challenge) hashPassword_256(password string) []byte {
	//var tempBuff [32]uint8
	//x := sha512.Sum512(publicKey[:])
	//h := sha256.New()
	pw_hash1 := sha256.Sum256([]byte(password))
	pw_hash2 := sha256.Sum256(pw_hash1[:32])
	//return h.Sum(h.Sum([]byte(password))[:32])[:12]
	return pw_hash2[:12]
}

func (c *CryptoAuth_Challenge) hashPassword(password string, authType int) {
	switch authType {
	case 1:
		c.hashPassword_256(password)
	default:
		log.Println("Error: hashPassword() Unsupported authType")
	}
}

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
type Handshake struct {
	layers.BaseLayer
	Stage uint32
	//Challenge     CryptoAuth_Challenge
	Challenge     [12]byte  // We use a generic container initially then decode it into appropriate struct later
	Nonce         [24]uint8 // 24 bytes
	PublicKey     [32]uint8
	Authenticator [16]uint8 // 16 bytes
	TempPublicKey [32]uint8 // 32 bytes
	buffer        []byte
}

//binary.Read(r, binary.BigEndian, &ca.Handshake.Stage)

var LayerTypeHandshake = gopacket.RegisterLayerType(1800,
	gopacket.LayerTypeMetadata{Name: "CryptoAuthHandshake",
		Decoder: gopacket.DecodeFunc(decodeHandshake)})

func (h *Handshake) LayerType() gopacket.LayerType {
	return LayerTypeHandshake
}

func decodeHandshake(data []byte, p gopacket.PacketBuilder) error {

	h := &Handshake{}
	err := h.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(h)
	p.SetApplicationLayer(h)
	return nil
}

func (h *Handshake) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	h.buffer = h.buffer[:0]

	if len(data) < 120 {
		df.SetTruncated()
		return fmt.Errorf("CryptoAuthHandshake header too short")
	}

	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &h.Stage)
	if ^h.Stage == 0 {
		log.Println("boobs")
	}
	log.Println("bigendian stage ", h.Stage)
	binary.Read(r, binary.BigEndian, &h.Challenge)
	binary.Read(r, binary.BigEndian, &h.Nonce)
	binary.Read(r, binary.BigEndian, &h.PublicKey)
	binary.Read(r, binary.BigEndian, &h.Authenticator)
	binary.Read(r, binary.BigEndian, &h.TempPublicKey)

	log.Printf("remote peer public key in b32: %s\n", base32Encode(h.PublicKey[:])[:52])

	return nil

}

func (h *Handshake) CanDecode() gopacket.LayerClass {
	return LayerTypeHandshake
}

func (h *Handshake) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (h *Handshake) Payload() []byte {
	return nil
}
