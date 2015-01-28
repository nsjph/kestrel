package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"log"
)

func hashPassword_256(password []byte) []byte {
	//var tempBuff [32]uint8
	//x := sha512.Sum512(publicKey[:])
	//h := sha256.New()
	pw_hash1 := sha256.Sum256(password)
	pw_hash2 := sha256.Sum256(pw_hash1[:32])
	//return h.Sum(h.Sum([]byte(password))[:32])[:12]

	log.Printf("original %s, hashed %x", password, pw_hash2[:12])
	return pw_hash2[:32]
}

func hashPassword(password []byte, authType int) []byte {
	switch authType {
	case 1:
		return hashPassword_256(password)
	default:
		log.Println("Error: hashPassword() Unsupported authType")
	}
	return nil
}

func (peer *Peer) getSharedSecret() {
	if peer.password == nil {
		log.Printf("getsharedsecret remote peer public key in b32: %s\n", base32Encode(peer.publicKey[:])[:52])
		box.Precompute(&peer.sharedSecret, &peer.publicKey, &peer.routerKeyPair.privateKey)
	} else {
		log.Printf("PASSWORD IS NOT NIL")

		var computedKey [32]byte
		curve25519.ScalarMult(&computedKey, &peer.routerKeyPair.privateKey, &peer.publicKey)

		buff := make([]byte, 64)
		copy(buff[:32], computedKey[:])
		copy(buff[32:64], peer.passwordHash[:])

		peer.sharedSecret = sha256.Sum256(buff)

		//:= make([]byte, 32)

		// compute crypto_scalarmult_curve25519 - shared key is buff[:32], passwordhash is buff[32:64],
		// and then buff is sha256 hashed
		//panic("write this part of getSharedSecret")
	}
}

func (router *Router) encryptHandshake(msg []byte, peer *Peer) []byte {
	h := &CryptoAuth_Handshake{}

	h.Stage = peer.nextNonce + 1
	h.Challenge.Type = 0
	z := make([]byte, 7)
	rand.Read(z)
	copy(h.Challenge.Lookup[:], z)
	//rand.Read(h.Challenge.Lookup)
	h.Challenge.RequirePacketAuthAndDerivationCount = 1
	h.Challenge.Additional = 1
	h.PublicKey = peer.routerKeyPair.publicKey
	n, err := rand.Read(h.Nonce[:])
	checkFatal(err)
	log.Println("random bytes read into h.Nonce", n)

	if peer.password != nil {
		passwordHash := hashPassword(peer.password, 1)
		router.Log.Debug("passwordHash = [%x]", passwordHash)
	}

	if peer.nextNonce == 0 || peer.nextNonce == 2 {
		// Generate temp keypair
		peer.tempKeyPair = createTempKeyPair()
		//peer.tempPublicKey, peer.tempPrivateKey = createTempKeyPair()
		h.TempPublicKey = peer.tempKeyPair.publicKey
	}

	if peer.nextNonce < 2 {
		// Generate shared secret
		peer.getSharedSecret()
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

	router.Log.Debug("sending message with:\n\tnonce: %x\n\tsecret: %x\n\tourPubkey: %x\n\therPubkey: %x\n",
		h.Nonce, peer.sharedSecret, peer.routerKeyPair.publicKey, peer.publicKey)

	//spew.Dump(buf.Bytes())

	//log.Printf("cryptoauth len: %d", len(buf.Bytes()))
	y := make([]byte, 72)
	copy(y[:len(buf.Bytes())], buf.Bytes())
	//log.Printf("msg before: %x", y)

	//encryptedMsg, authenticator := encryptRandomNonce(h.Nonce, y, peer.sharedSecret)
	//copy(h.Authenticator[:], authenticator)

	// p := gopacket.NewPacket(buf.Bytes(), LayerTypeHandshake, gopacket.Lazy)

	// var h2 *Handshake

	// if handshakeLayer := p.Layer(LayerTypeHandshake); handshakeLayer != nil {
	// 	router.Log.Debug("XXX This is a handshake packet!")
	// 	h2, _ = handshakeLayer.(*Handshake)
	// 	router.Log.Debug("handshake stage: %d", h2.Stage)

	// 	//router.Log.Debug("outbound packet: %s", p.String())

	// 	// for _, layer := range p.Layers() {
	// 	//  log.Println("PACKET LAYER:", layer.LayerType)
	// 	// }
	// 	//router.Log.Debug(p.LayerDump(gopacket.ApplicationLayer))
	// }

	return nil
}

// Assume this is already host endian format
func getAuthChallengeDerivations(derivations uint16) uint16 {
	return derivations & ^uint16(0) >> 1
}

// We don't convert endianness here, we do that when writing out the final packet
func (c *CryptoAuth_Challenge) setAuthChallengeDerivations(derivations uint16) {
	c.RequirePacketAuthAndDerivationCount &= (1 << 15)
	c.RequirePacketAuthAndDerivationCount |= derivations & ^uint16(1<<15)
}

func (c *CryptoAuth_Challenge) setSetupPacket(empty int) {
	if empty == 1 {
		c.Additional |= (1 << 15)
	} else {
		c.Additional &= ^uint16(1 << 15)
	}
}

func (c *CryptoAuth_Challenge) setPacketAuthRequired(require int) {
	if require == 1 {
		c.RequirePacketAuthAndDerivationCount |= (1 << 15)
	} else {
		c.RequirePacketAuthAndDerivationCount &= ^uint16(1 << 15)
	}
}

func (c *CryptoAuth_Challenge) isSetupPacket() uint16 {
	return (c.Additional & (1 << 15))
}

// Hello Packet experimentation

type HelloPacket struct {
	Stage         uint32
	Challenge     *CryptoAuth_Challenge // We use a generic container initially then decode it into appropriate struct later
	Nonce         [24]byte              // 24 bytes
	PublicKey     [32]byte
	Authenticator [16]byte // 16 bytes
	TempPublicKey [32]byte // 32 bytes
}

// type CryptoAuth_Challenge struct {
//  Type                                uint8
//  Lookup                              [7]byte
//  RequirePacketAuthAndDerivationCount uint16
//  Additional                          uint16
// }

func encryptRandomNonce2(nonce [24]byte, msg *Message, secret [32]byte) []byte {

	startAt := make([]byte, len(msg.payload))
	copy(startAt[:], msg.payload[512:])
	encryptedMsg := box.SealAfterPrecomputation(startAt, startAt, &nonce, &secret)

	log.Printf("encryptRandomNonce(): message = [%x]", startAt)
	log.Printf("encryptRandomNonce(): encryptedmessage = [%x]", encryptedMsg)

	return encryptedMsg
}

func encryptRandomNonce(nonce [24]byte, msg []byte, secret [32]byte) []byte {

	//startAt := make([]byte, len(msg.payload))
	//copy(startAt[:], msg.payload[512:])
	//out := make([]byte, len(msg)+32)
	//var out []byte

	log.Printf("encryptRandomNonce(): orig msg = [%x]", msg)

	encryptedMsg := box.SealAfterPrecomputation(msg, msg, &nonce, &secret)

	log.Printf("encryptRandomNonce(): message = [%x]", msg)
	log.Printf("encryptRandomNonce(): out = [%x]", msg)
	log.Printf("encryptRandomNonce(): encryptedmessage = [%x]", encryptedMsg)

	return encryptedMsg
}

func (peer *Peer) decryptHandshake(data []byte) {

}

func decryptRandomNonce(nonce [24]byte, msg []byte, sharedSecret [32]byte) {

}

func (peer *Peer) newHelloPacket() []byte {
	h := new(HelloPacket)
	h.Challenge = new(CryptoAuth_Challenge)

	// note, at this stage we're not garbaging the challenge 12 bytes

	nonce := make([]byte, 24)
	rand.Read(nonce)
	copy(h.Nonce[:], nonce)

	h.PublicKey = peer.routerKeyPair.publicKey
	//peer.log.Debug("newHelloPacket(): setting our perm pubkey to [%s]", keyToHex(h.PublicKey))

	if peer.password != nil {
		copy(peer.passwordHash[:], hashPassword(peer.password, 1))
		h.Challenge.Type = 1
	} else {
		h.Challenge.Type = 0
	}

	//h.Challenge.Type = 1

	h.Challenge.setPacketAuthRequired(1)
	h.Challenge.setSetupPacket(0)

	h.Stage = peer.nextNonce

	peer.tempKeyPair = createTempKeyPair()
	h.TempPublicKey = peer.tempKeyPair.publicKey

	// if hello or key packet, generate tempkey and assign to temppubkey
	if peer.nextNonce == 0 || peer.nextNonce == 2 {
		peer.tempKeyPair = createTempKeyPair()
		h.TempPublicKey = peer.tempKeyPair.publicKey
	}

	if peer.nextNonce < 2 {
		// get shared secret
		peer.getSharedSecret()
		peer.initiator = true
		peer.nextNonce = 1
	} else {
		peer.getSharedSecret()
		peer.nextNonce = 3
	}

	log.Printf("pre-newMessage: msg = [%x]", h.TempPublicKey)
	m := newMessage2(h.TempPublicKey[:])
	//n := messageNew([]byte("hi there"))
	encryptedMsg := encryptRandomNonce(h.Nonce, m, peer.sharedSecret)

	//binary.BigEndian.PutUint32

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Stage)
	binary.Write(buf, binary.BigEndian, h.Challenge.Type)
	binary.Write(buf, binary.BigEndian, h.Challenge.Lookup)
	binary.Write(buf, binary.BigEndian, h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Write(buf, binary.BigEndian, h.Challenge.Additional)
	binary.Write(buf, binary.BigEndian, h.Nonce)
	binary.Write(buf, binary.LittleEndian, h.PublicKey)
	//binary.Write(buf, binary.BigEndian, h.Authenticator)
	binary.Write(buf, binary.BigEndian, encryptedMsg)
	//binary.Write(buf, binary.BigEndian, uint32(512))
	//binary.Write(buf, binary.BigEndian, uint32(len(m)))

	peer.log.Debug("Encrypting message with:\n nonce: %x\n secret: %x\n cipher: %x\n", h.Nonce, peer.sharedSecret, encryptedMsg)

	return buf.Bytes()

}

func (peer *Peer) sendHelloPacket(packet []byte) {
	n, err := peer.conn.WriteToUDP(packet, peer.addr)
	checkFatal(err)
	peer.log.Debug("wrote %d bytes to peer %s", n, peer.name)
}
