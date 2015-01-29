package main

import (
	"bytes"
	_ "bytes"
	_ "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"log"
)

const (
	CryptoHeader_MAXLEN                       = 120
	CryptoAuth_RESET_AFTER_INACTIVITY_SECONDS = 60
)

type CryptoAuth_Challenge struct {
	Type                                uint8
	Lookup                              [7]byte
	RequirePacketAuthAndDerivationCount uint16
	Additional                          uint16
}

type CryptoAuth_Handshake struct {
	Stage     uint32
	Challenge *CryptoAuth_Challenge // We use a generic container initially then decode it into appropriate struct later
	Nonce     [24]byte              // 24 bytes
	PublicKey [32]byte
	//AuthenticatorAndencryptedTempPubKey []byte
	Authenticator [16]byte // 16 bytes
	TempPublicKey [32]byte // 32 bytes
}

func decodeHandshake(data []byte) (*CryptoAuth_Handshake, error) {
	h := new(CryptoAuth_Handshake)
	h.Challenge = new(CryptoAuth_Challenge)

	// h.buffer = h.buffer[:0]

	if len(data) < 120 {
		return nil, fmt.Errorf("CryptoAuthHandshake header too short")
	}

	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &h.Stage)
	binary.Read(r, binary.BigEndian, &h.Challenge.Type)
	binary.Read(r, binary.BigEndian, &h.Challenge.Lookup)
	binary.Read(r, binary.BigEndian, &h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Read(r, binary.BigEndian, &h.Challenge.Additional)
	binary.Read(r, binary.BigEndian, &h.Nonce)
	binary.Read(r, binary.BigEndian, &h.PublicKey)
	binary.Read(r, binary.BigEndian, &h.Authenticator)
	binary.Read(r, binary.BigEndian, &h.TempPublicKey)
	//binary.Read(r, binary.BigEndian, &h.AuthenticatorAndencryptedTempPubKey)
	return h, nil
}

func hashPassword_256(password []byte) (passwordHash [32]byte) {

	pw_hash1 := sha256.Sum256(password)
	pw_hash2 := sha256.Sum256(pw_hash1[:32])

	copy(passwordHash[:], pw_hash2[:32])

	return passwordHash

	//log.Printf("original %s, hashed %x", password, pw_hash2[:12])
	//return pw_hash2[:32]
}

func hashPassword(password []byte, authType int) (passwordHash [32]byte) {
	switch authType {
	case 1:
		passwordHash = hashPassword_256(password)
		//return hashPassword_256(password)
	default:
		log.Println("Error: hashPassword() Unsupported authType")
	}
	// TODO: review this...
	return passwordHash
}

func computeSharedSecret(privateKey [32]byte, herPublicKey [32]byte) (sharedSecret [32]byte) {

	// TODO: check this, is this right way to check for empty [32]byte?
	box.Precompute(&sharedSecret, &herPublicKey, &privateKey)
	return sharedSecret
}

func computeSharedSecretWithPasswordHash(privateKey [32]byte, herPublicKey [32]byte, passwordHash [32]byte) (sharedSecret [32]byte) {

	// TODO: check this, is this right way to check for empty [32]byte?

	var computedKey [32]byte
	curve25519.ScalarMult(&computedKey, &privateKey, &herPublicKey)

	buff := make([]byte, 64)
	copy(buff[:32], computedKey[:])
	copy(buff[32:64], passwordHash[:])

	sharedSecret = sha256.Sum256(buff)

	return sharedSecret
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

func decryptRandomNonce(nonce [24]byte, msg []byte, sharedSecret [32]byte) ([]byte, bool) {

	var out []byte

	decrypted, success := box.OpenAfterPrecomputation(out, msg, &nonce, &sharedSecret)
	//spew.Dump(msg)

	return decrypted, success
}

// this is horribly inefficient i think, because i'm a golang/binary noob --jph

func encrypt(nonce uint32, msg []byte, sharedSecret [32]byte, initiator bool) []byte {

	//var littleEndianNonce uint32

	//littleEndianNonce := binary.LittleEndian.Uint32([]byte(nonce))

	n := make([]byte, 8)
	var convertedNonce [24]byte

	if initiator == true {
		binary.LittleEndian.PutUint32(n[4:], nonce)
	} else {
		binary.LittleEndian.PutUint32(n[:4], nonce)
		//n[0] = littleEndianNonce
	}

	copy(convertedNonce[:], n)

	//buf := new(bytes.Buffer)
	//binary.Write(buf, binary.BigEndian, n)

	spew.Printf("encrypt(): convertedNonce = %v", convertedNonce)

	return encryptRandomNonce(convertedNonce, msg, sharedSecret)

	//return convertedNonce

}

func decrypt(nonce uint32, encryptedData []byte, sharedSecret [32]byte, initiator bool) [24]byte {

	n := make([]byte, 8)
	var convertedNonce [24]byte

	if initiator == false {
		binary.LittleEndian.PutUint32(n[4:], nonce)
	} else {
		binary.LittleEndian.PutUint32(n[:4], nonce)
		//n[0] = littleEndianNonce
	}

	copy(convertedNonce[:], n)

	//buf := new(bytes.Buffer)
	//binary.Write(buf, binary.BigEndian, n)

	spew.Printf("decrypt(): convertedNonce = %v", convertedNonce)

	return convertedNonce

}

func (auth *CryptoAuth_Auth) getAuth(challengeAsBytes [12]byte, peer *Peer) *Account {
	// Check the challenge.Type == 1
	if challengeAsBytes[0] != 1 {
		peer.log.Warning("getAuth: invalid auth type")
		// TODO: make sure calling function checks that this is empty
		return nil
	}

	for _, v := range auth.accounts {
		if v == nil {
			auth.log.Debug("getAuth: v == nil")
			return nil
		}
		if isEmpty(v.secret) {
			auth.log.Debug("getAuth: v.secret is empty")
			return nil
		}
		// Check for match, if so return the full secret
		var a []byte
		var b []byte
		copy(a, challengeAsBytes[0:8])
		copy(b, v.secret[0:8])
		if bytes.Compare(a, b) == 0 {
			return v
		}
	}

	// TODO: Check calling function checks if this is empty
	return nil

}

func (peer *Peer) getPasswordHash_typeOne(derivations uint16) [32]byte {
	if derivations != uint16(0) {
		var output [32]byte
		copy(output[:], peer.sharedSecret[:32])
		b := make([]byte, 2)
		// littleEndian case from encoding/binary.go
		b[0] = byte(derivations)
		b[1] = byte(derivations >> 8)

		output[0] ^= b[0]
		output[1] ^= b[1]

		spew.Printf("getPasswordHash_typeOne(%v) -> [%v]", derivations, output)

		return sha256.Sum256(output[:])

		//buf := bytes.NewReader(derivations)
		//x := binary.Read()
	}

	return [32]byte{}

}

func (peer *Peer) tryAuth(h *CryptoAuth_Handshake, challengeAsBytes [12]byte, account *Account, auth *CryptoAuth_Auth) (x [32]byte) {

	account = auth.getAuth(challengeAsBytes, peer)

	if h.Challenge != nil {
		derivations := getAuthChallengeDerivations(h.Challenge.RequirePacketAuthAndDerivationCount)
		passwordHash := peer.getPasswordHash_typeOne(derivations)
		spew.Printf("tryAuth: derivations = [%v]", derivations)
		if derivations == 0 {
			peer.log.Debug("tryAuth: derivations == 0, not sure what to do")
			return [32]byte{}
		}
		return passwordHash
	}

	// TODO: fix this
	panic("tryAuth: I dont know how to tryauth")
	return x

}

//func addUser ()
