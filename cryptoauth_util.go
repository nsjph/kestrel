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

	pw_hash1 := sha256.Sum256(password)
	pw_hash2 := sha256.Sum256(pw_hash1[:32])

	//log.Printf("original %s, hashed %x", password, pw_hash2[:12])
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
	}
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

// encryptRandomNonce uses the nonce and shared secret to encrypt the
// temp public key.
//
// encryptedMsg[:16] = authenticator / [16]byte
// encryptedMsg[16:] = encryptedTempPublicKey / [32]byte
//
// TODO: Maybe encryptedMsg isn't the best name for the variable

func encryptRandomNonce(nonce [24]byte, msg []byte, secret [32]byte) []byte {

	// TODO: confirm if this is necessary
	var out []byte

	encryptedMsg := box.SealAfterPrecomputation(out, msg, &nonce, &secret)

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
	//h.TempPublicKey = peer.tempKeyPair.publicKey
	peer.log.Debug("peer.tempPublicKey = [%x]", peer.tempKeyPair.publicKey)
	//peer.log.Debug("head.tempPublicKey = [%x]", h.TempPublicKey)

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

	//binary.BigEndian.PutUint32

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Stage)
	binary.Write(buf, binary.BigEndian, h.Challenge.Type)
	binary.Write(buf, binary.BigEndian, h.Challenge.Lookup)
	binary.Write(buf, binary.BigEndian, h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Write(buf, binary.BigEndian, h.Challenge.Additional)
	binary.Write(buf, binary.BigEndian, h.Nonce)
	binary.Write(buf, binary.BigEndian, h.PublicKey)
	//binary.Write(buf, binary.BigEndian, h.Authenticator)
	//binary.Write(buf, binary.BigEndian, encryptedMsg)
	//binary.Write(buf, binary.BigEndian, uint32(512))
	//binary.Write(buf, binary.BigEndian, uint32(len(m)))

	//log.Printf("pre-newMessage: msg = [%x]", h.TempPublicKey)
	//m := newMessage2(h.)
	//n := messageNew([]byte("hi there"))
	//m := make([]byte, 32)
	//copy(m, peer.tempKeyPair.publicKey[:])

	peer.log.Debug("pre-encrypt header: %x", buf.Bytes())

	encryptedMsg := encryptRandomNonce(h.Nonce, peer.tempKeyPair.publicKey[:], peer.sharedSecret)

	peer.log.Debug("encryptedMsg length = [%d]", len(encryptedMsg))

	peer.log.Debug("Encrypting message with:\n nonce: %x\n secret: %x\n cipher: %x\n", h.Nonce, peer.sharedSecret, encryptedMsg)

	binary.Write(buf, binary.BigEndian, encryptedMsg)

	return buf.Bytes()

}

func (peer *Peer) sendHelloPacket(packet []byte) {
	n, err := peer.conn.WriteToUDP(packet, peer.addr)
	checkFatal(err)
	peer.log.Debug("wrote %d bytes to peer %s", n, peer.name)
}
