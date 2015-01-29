// cryptoauth.go

package main

import (
	"bytes"
	_ "code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/binary"
	_ "encoding/hex"
	"errors"
	_ "golang.org/x/crypto/curve25519"
	_ "golang.org/x/crypto/nacl/box"
	_ "log"
	"math"
	_ "math"
)

func (peer *Peer) receiveMessage(msg []byte) (int, []byte, error) {
	if len(msg) < 20 {
		peer.log.Warning("receiveMessage(): packet too short, dropping")
		return -1, nil, errors.New("Error_UNDERSIZE_MESSAGE")
	}

	nonce := binary.BigEndian.Uint32(msg[:4])
	peer.log.Debug("receiveMessage: nonce is [%u]", nonce)

	if peer.established != true {
		if nonce > 3 && nonce != math.MaxUint32 {
			if peer.nextNonce < 3 {
				peer.log.Debug("receiveMessage: Dropping message to an unsetup connection")
				return -1, nil, errors.New("Error_UNDELIVERABLE")
			}

			peer.log.Debug("receiveMessage: Trying to complete handshake, nonce=%u", nonce)
			sharedSecret := computeSharedSecret(peer.tempKeyPair.privateKey, peer.publicKey)
			peer.nextNonce += 3

			// return code, body of decrypted message, error message
			ret, _, _ := peer.decryptMessage(nonce, msg[4:], sharedSecret)
			if ret == 0 { // success
				peer.log.Debug("receiveMessage: Handshake completed!")
				peer.sharedSecret = sharedSecret
				peer.established = true

				// do something
			}

			peer.log.Debug("receiveMessage: Final handshake failed")
			return -1, nil, errors.New("Error_UNDERLIVERABLZ")

		}

		return 0, peer.decryptHandshake(nonce, msg), nil

	} else if nonce > 3 && nonce != math.MaxUint32 {
		ret, _, _ := peer.decryptMessage(nonce, msg, peer.sharedSecret)
		if ret == 0 {
			// do something
			panic("what do i do with a decrypted message!?")
		} else {
			peer.log.Debug("receiveMessage: failed to decrypt message")
			return -1, nil, errors.New("Error_UNDELIVERABEL")
		}

	}

	return -1, nil, errors.New("Error_FELLTHRURECEIVMSG")
}

func (peer *Peer) sendMessage(msg []byte) {
	// TODO: Check if there has been incoming traffic. If timeout reached, reset connection  to 0

	if peer.nextNonce >= 0xfffffff0 {
		// TODO: reset the nonce
		panic("sendMessage: write the nonce resetting code")
	}

	if peer.nextNonce < 5 {
		if peer.nextNonce < 4 {
			n, err := peer.conn.WriteToUDP(peer.encryptHandshake(msg, 0), peer.addr)
			checkFatal(err)
			peer.log.Debug("Peer.sendMessage(): wrote %d bytes of encrypted handshake to peer %s", n, peer.name)
			return
		} else {
			peer.log.Debug("sendMessage: final step to send handshake, nonce = 4")
			peer.sharedSecret = computeSharedSecret(peer.tempKeyPair.privateKey, peer.publicKey)
		}
	}

	n, err := peer.conn.WriteToUDP(peer.encryptMessage(msg), peer.addr)
	checkFatal(err)
	peer.log.Debug("sendMessage: wrote %d bytes of encrypted message to peer %s", n, peer.name)

}

func (peer *Peer) encryptMessage(msg []byte) []byte {

	encryptedMsg := encrypt(peer.nextNonce, msg, peer.sharedSecret, peer.initiator)
	peer.nextNonce++

	return encryptedMsg

}

func (peer *Peer) decryptMessage(nonce uint32, encryptedPayload []byte, sharedSecret [32]byte) (int, []byte, error) {
	panic("i dont know how to decrypt a message")
	return 0, nil, nil
}

func (peer *Peer) sendHandshake(packet []byte) {
	n, err := peer.conn.WriteToUDP(packet, peer.addr)
	checkFatal(err)
	peer.log.Debug("wrote %d bytes to peer %s", n, peer.name)
}

func (peer *Peer) resetSession() {
	peer.nextNonce = 0
	peer.initiator = false
	// TODO: verify that this is effective for resetting the pub/private keys
	peer.tempKeyPair = new(KeyPair)
	//peer.tempKeyPair.privateKey = [32]byte{}

	// TODO: how do you zero a struct? Is this ok?
	peer.replayProtector = new(ReplayProtector)
}

func (peer *Peer) decryptHandshake(nonce uint32, data []byte) []byte {

	if len(data) < CryptoHeader_MAXLEN {
		peer.log.Warning("decryptHandshake: short packet received from %s", peer.name)
		// TODO: have calling function check for nil from decryptHandshake
		return nil
	}

	handshake, err := decodeHandshake(data)
	checkFatal(err)

	if isEmpty(peer.publicKey) == false {
		if peer.publicKey != handshake.PublicKey {
			peer.log.Warning("decryptHandshake: dropping packet with different public key to existing session")
		}
	} // TODO: add state check for ip6 match

	if peer.nextNonce < 2 && nonce == math.MaxUint32 && peer.requireAuth == false {
		// TODO: write connect-to-me response code
		peer.resetSession()
		// TODO: check for success of encryptedHandshake
		encryptedHandshake := peer.encryptHandshake(data, 1)
		return encryptedHandshake
	}

	panic("i dont know how to decrypt a handshake")
	return nil
}

func (peer *Peer) encryptHandshake(msg []byte, isSetup int) []byte {
	h := new(CryptoAuth_Handshake)
	h.Challenge = new(CryptoAuth_Challenge)
	var passwordHash [32]byte

	nonce := make([]byte, 24)
	rand.Read(nonce)
	copy(h.Nonce[:], nonce)

	h.PublicKey = peer.routerKeyPair.publicKey

	if peer.password != nil {
		passwordHash = hashPassword(peer.password, 1)
		//copy(peer.passwordHash[:], hashPassword(peer.password, 1))
		h.Challenge.Type = 1
	} else {
		h.Challenge.Type = 0
	}

	h.Challenge.setPacketAuthRequired(1)
	h.Challenge.setSetupPacket(0)

	h.Stage = peer.nextNonce

	peer.tempKeyPair = createTempKeyPair()

	if peer.nextNonce == 0 || peer.nextNonce == 2 {
		peer.tempKeyPair = createTempKeyPair()
		h.TempPublicKey = peer.tempKeyPair.publicKey
	}

	if peer.nextNonce < 2 {
		computeSharedSecretWithPasswordHash(peer.routerKeyPair.privateKey, peer.publicKey, passwordHash)
		peer.initiator = true
		peer.nextNonce = 1
	} else {
		computeSharedSecretWithPasswordHash(peer.routerKeyPair.privateKey, peer.publicKey, passwordHash)
		peer.nextNonce = 3
	}

	authenticatorAndEncryptedTempPubKey := encryptRandomNonce(h.Nonce, peer.tempKeyPair.publicKey[:], peer.sharedSecret)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Stage)
	binary.Write(buf, binary.BigEndian, h.Challenge.Type)
	binary.Write(buf, binary.BigEndian, h.Challenge.Lookup)
	binary.Write(buf, binary.BigEndian, h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Write(buf, binary.BigEndian, h.Challenge.Additional)
	binary.Write(buf, binary.BigEndian, h.Nonce)
	binary.Write(buf, binary.BigEndian, h.PublicKey)
	binary.Write(buf, binary.BigEndian, authenticatorAndEncryptedTempPubKey)

	peer.log.Debug("Encrypting handshake with:\n nonce: %x\n secret: %x\n cipher: %x\n", h.Nonce, peer.sharedSecret, authenticatorAndEncryptedTempPubKey)

	return buf.Bytes()

}
