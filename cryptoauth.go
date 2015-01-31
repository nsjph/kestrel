// cryptoauth.go

package main

import (
	"bytes"
	_ "code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"crypto/rand"
	"encoding/binary"
	_ "encoding/hex"
	_ "errors"
	_ "fmt"
	_ "github.com/davecgh/go-spew/spew"
	"github.com/op/go-logging"
	_ "github.com/sirupsen/logrus"
	_ "golang.org/x/crypto/curve25519"
	_ "golang.org/x/crypto/nacl/box"
	_ "log"
	"math"
	_ "math"
)

// type CryptoAuthMessage struct {
// 	Type     MessageType // type, either cryptoauth.handshake or cryptoauth.data
// 	Code     int         // code - state of the message, mainly for handshakes
// 	Checksum int         // checksum -- probably unecessary
// 	Body     MessageBody // body
// }

// type CryptoAuthMessageBody struct {

// }

func parseCryptoAuthMessage(data []byte, log *logging.Logger, peer *Peer) (*Message, error) {

	var nonce uint32 = binary.BigEndian.Uint32(data[0:4])

	if peer.established == false {
		if nonce > 3 && nonce != math.MaxUint32 {
			if peer.nextNonce < 3 {
				log.Notice("Dropping cryptoauth message to an unsetup session")
				return nil, errUndeliverable
			}
		}
	}

	return nil, nil
}

func (peer *Peer) receiveMessage(msg []byte, auth *CryptoAuth_Auth) error {
	if len(msg) < 20 {
		peer.log.Warning("receiveMessage(): packet too short, dropping")
		return errUndersizeMessage
	}

	nonce := binary.BigEndian.Uint32(msg[:4])
	//peer.log.Debug("receiveMessage: littleEndian nonce is [%v], bigEndian nonce is [%v]", binary.LittleEndian.Uint32(msg[:4]), nonce)

	peer.log.Debugf("receiveMessage:\n\tnonce = [%d]\n\tpeer.nextNonce = [%d]", nonce, peer.nextNonce)

	if peer.established == false {
		if nonce > 3 && nonce != math.MaxUint32 {
			if peer.nextNonce < 3 {
				peer.log.Debug("receiveMessage: Dropping message to an unsetup connection")
				return errUndeliverable.addDetails("Dropping message to unsetup connection")
				//return -1, nil, errors.New("Error_UNDELIVERABLE")
			}

			peer.log.Debugf("receiveMessage: Trying to complete handshake, nonce=%u", nonce)
			peer.log.Debugf("generating a shared secret:\n\tmyPublicKey [%x]\n\therPublicKey [%x]",
				peer.tempKeyPair.publicKey, peer.tempPublicKey)
			sharedSecret := computeSharedSecret(peer.tempKeyPair.privateKey, peer.tempPublicKey)
			peer.nextNonce += 3

			////
			// decryptMessage and mark handshake complete
			////

			_, err := peer.decryptMessage(nonce, msg[4:], sharedSecret)
			switch err.Code {
			case ERROR_NONE:
				peer.log.Info("Handshake completed with peer")
				peer.sharedSecret = sharedSecret
				peer.established = true
				panic("handle decrypted message now")
			default:
				peer.log.Warningf("Decrypting message failed with error %s (%s)", err.Message, err.Details)
				return nil
			}

			// peer.log.Debug("receiveMessage: Final handshake failed")
			// return errUndeliverable.addDetails("final handshake failed")

		}

		err := peer.decryptHandshake(msg, auth)
		switch err.Code {
		case ERROR_NONE:
			switch peer.nextNonce {
			case 0:
				panic("nextNonce is 0")
			case 1:
				panic("nextNonce is 1")
			case 2:
				return peer.sendMessage([]byte{}, auth)
			case 3:
				return peer.sendMessage([]byte{}, auth)
				//panic("help me handle a key packet (3)")
			default:
				peer.log.Debugf("receiveMessage: no issue decrypting handshake, but what do I do with nonce %d", peer.nextNonce)
			}
		default:
			peer.log.Debug("receiveMessage: decrypting handshake error: %s: %s", err.Message, err.Details)
			return errUnknown

		}

	} else if nonce > 3 && nonce != math.MaxUint32 {
		_, err := peer.decryptMessage(nonce, msg, peer.sharedSecret)
		switch err.Code {
		case ERROR_NONE:
			panic("what do I do with a decrypted message?")
		default:
			peer.log.Warningf("Failed to decrypt message: %s (%s)", err.Message, err.Details)
			return errAuthentication
		}

	}

	return errNotImplemented.addDetails("fell through to end of receiveMessage")
}

func (peer *Peer) sendMessage(msg []byte, auth *CryptoAuth_Auth) error {
	// TODO: Check if there has been incoming traffic. If timeout reached, reset connection  to 0

	if peer.nextNonce >= 0xfffffff0 {
		// TODO: reset the nonce
		panic("sendMessage: write the nonce resetting code")
	}

	if peer.nextNonce < 5 {
		if peer.nextNonce < 4 {
			encryptedHandshake, err := peer.encryptHandshake(msg, 0, auth)
			switch err.Code {
			case ERROR_NONE:
				peer.log.Debug("sendMessage: sending encrypted handshake to peer")
				n, err := peer.conn.WriteToUDP(encryptedHandshake, peer.addr)
				if err != nil {
					peer.log.Debug("sendMessage: error sending encrypted handshake: %v", err)
					return err
				} else {
					peer.log.Debug("sendMessage: sent encrypted handshake, wrote %d bytes", n)
					return errNone

				}
				return err
			default:
				peer.log.Debug("sendMessage: error %s: %s", err.Message, err.Details)
				return err
			}

			// n, err := peer.conn.WriteToUDP(peer.encryptHandshake(msg, 0, auth), peer.addr)
			// checkFatal(err)
			// peer.log.Debug("Peer.sendMessage(): wrote %d bytes of encrypted handshake to peer %s", n, peer.name)

		} else {
			peer.log.Debug("sendMessage: final step to send handshake, nonce = 4")
			peer.sharedSecret = computeSharedSecret(peer.tempKeyPair.privateKey, peer.publicKey)
		}
	}

	n, err := peer.conn.WriteToUDP(peer.encryptMessage(msg), peer.addr)
	checkFatal(err)
	peer.log.Debug("sendMessage: wrote %d bytes of encrypted message to peer %s", n, peer.name)

	return errNone.addDetails("Reached end of sendMessage")

}

func (peer *Peer) encryptMessage(msg []byte) []byte {

	encryptedMsg := encrypt(peer.nextNonce, msg, peer.sharedSecret, peer.initiator)
	peer.nextNonce++

	return encryptedMsg

}

func (peer *Peer) decryptMessage(nonce uint32, data []byte, sharedSecret [32]byte) ([]byte, *cjdnsError) {

	peer.log.Debugf("decrypting message with:\n\tnonce: [%d]\n\tsecret: [%x]\n\tpeerSecret: [%x]",
		nonce, sharedSecret, peer.sharedSecret)
	decryptedMessage, success := peer.decrypt(nonce, data, sharedSecret, peer.initiator)

	if success == true {
		peer.log.Debugf("decryptMessage: successfully decrypted message")
		return decryptedMessage, errNone
	} else if success == false {
		peer.log.Debugf("decryptMessage: decryption failed")
		return nil, errAuthentication.addDetails("decryptMessage: decryption failed")
	}

	panic("i dont know how to decrypt a message")
	return nil, errUnknown
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

////
// decryptHandshake is a significant part of cryptoauth, because of the
// significant if-then-that conditions to ensure that the session is correctly
// established at both ends. Here be dragons (aka, a lot of control flow logic)
////

func (peer *Peer) decryptHandshake(data []byte, auth *CryptoAuth_Auth) *cjdnsError {

	if len(data) < 20 {
		peer.log.Info("decryptHandshake: short packet received from %s", peer.name)
		return nil
	}

	handshake, err := decodeHandshake(data)
	var nonce uint32 = handshake.Stage
	// TODO: do we need it to be a fixed-size? or can we use a []byte slice?
	var challengeAsBytes [12]byte
	copy(challengeAsBytes[:], data[4:16])

	encryptedTempPubKey := make([]byte, 200)
	copy(encryptedTempPubKey, data[68:])

	checkFatal(err)

	if isEmpty(peer.publicKey) == false {
		if peer.publicKey != handshake.PublicKey {
			peer.log.Info("decryptHandshake: dropping packet with different public key to existing session")
		}
	} // TODO: add state check for ip6 match

	if peer.nextNonce < 2 && nonce == math.MaxUint32 && peer.requireAuth == false {
		// TODO: write connect-to-me response code
		peer.resetSession()
		// TODO: check for success of encryptedHandshake
		// TODO: send encryptedHandshake response

		return errNotImplemented

		// panic("decryptHandshake: dont know how to send an encryptedHandshake")
		// encryptedHandshake := peer.encryptHandshake(data, 1)
		// return encryptedHandshake
	}

	//account := Account{}
	account, err := peer.tryAuth(handshake, challengeAsBytes, auth)

	////
	// Pre-decryption checks - these can probably be moved to some sort of 'validate packet' function
	////

	if peer.requireAuth && isEmpty(account.secret) {
		//spew.Dump(account)
		peer.log.Info("decryptHandshake: Dropping packet because no matching password found")
		return errAuthentication
	}

	if isEmpty(account.secret) && handshake.Challenge.Type != 0 {
		peer.log.Info("decryptHandshake: Dropping packet with unrecognized auth")
		return newError(ERROR_AUTHENTICATION, "decryptHandshake: Dropping packet with unrecognized auth")
	}

	peer.passwordHash = account.secret

	var nextNonce uint32 = handshake.Stage

	if nonce < 2 {
		if nonce == 0 {
			peer.log.Debug("Received a hello packet")
		} else {
			peer.log.Debug("received a repeat hello")
		}

		if isEmpty(peer.publicKey) || peer.nextNonce == 0 {
			peer.publicKey = handshake.PublicKey
		} else if peer.publicKey != handshake.PublicKey {
			peer.log.Info("decryptHandshake: Dropping packet with wrong permanent public key")
			return errAuthentication.addDetails("Dropping packet with wrong permanent public key")
		}

		peer.sharedSecret = computeSharedSecretWithPasswordHash(auth.keyPair.privateKey, peer.publicKey, account.secret)
		nextNonce = 2

	} else {
		if nonce == 2 {
			peer.log.Debug("decryptHandshake: received a key packet")
		} else if nonce == 3 {
			peer.log.Debug("decryptHandshake: received a repeat key packet")
		} else {
			peer.log.Debug("decryptHandshake: received a packet of unknown type. nonce = [%u]", nonce)
		}

		if peer.initiator == false {
			peer.log.Warning("decryptHandshake: Dropping a stray key packet")
			return errAuthentication.addDetails("Dropping a stray key packet")
		}

		peer.log.Debugf("Generating a key message for stage 4 of handshake")

		peer.sharedSecret = computeSharedSecretWithPasswordHash(peer.tempKeyPair.privateKey, peer.publicKey, account.secret)
		nextNonce = 4

	}

	////
	// Decrypt peer's temp public key
	////

	payload := data[72:] // 72 is where the encrypted portion begins
	var herTempPublicKey [32]byte

	// This is more than just the handshake
	decryptedHandshake, success := decryptRandomNonce(handshake.Nonce, payload, peer.sharedSecret)
	//copy(herTempPublicKey[:], decryptedHandshake[88:120])
	//decryptedTempPublicKey := decryptedHandshake[88:120]
	if success == false {
		peer.log.Info("decryptHandshake: Dropping message, decryption failed")
		peer.established = false
		return errAuthentication.addDetails("Dropping message, handshake decryption failed")
	} else {

		copy(herTempPublicKey[:], decryptedHandshake[88:120])
		peer.log.Debugf("decryptHandshake: temp public [%x]", herTempPublicKey)
		// TODO: need an assert to validate that we only got 32 bytes back from decrypting the handshake

		// TODO: this copy step is probably unecessary
		//copy(herTempPublicKey[:], decryptedTempPublicKey)
		//peer.tempPublicKey = herTempPublicKey
	}

	////
	// Post-decryption checks
	////

	if nonce == 0 {
		if peer.tempPublicKey == herTempPublicKey {
			peer.log.Warning("decryptHandshake: Dropping dupe hello packet with same temporary key")
			return errAuthentication.addDetails("Dropping dupe hello packet with same temp key")
		}
	} else if nonce == 2 && peer.nextNonce >= 4 {
		if peer.tempPublicKey == herTempPublicKey {
			peer.log.Warning("decryptHandshake: Dropping dupe key packet with same temporary public key")
			return errAuthentication.addDetails("Dropping dupe key packet with same temp public key")
		}

	} else if nonce == 3 && peer.nextNonce >= 4 {
		if peer.tempPublicKey != herTempPublicKey {
			peer.log.Debug("decryptHandshake: Dropping repeat key packet with different temporary public key")
			return errAuthentication.addDetails("Dropping repeat key packet with different temporary public key")
		}

	}

	// Check for repeat key packet and avoid deadlock

	// TODO: This part is untested, fix
	if nextNonce == 4 {
		if peer.nextNonce <= 4 {
			peer.nextNonce = nextNonce
			peer.tempPublicKey = herTempPublicKey
		} else {
			// Possibly repeat key packet for an established session
			peer.sharedSecret = computeSharedSecret(peer.tempKeyPair.privateKey, peer.tempPublicKey)
			peer.log.Warning("decryptHandshake: New key packet but we are already sending data")
		}
	} else if nextNonce != 2 {
		peer.log.Warning("decryptHandshake: Shouldn't reach here")
		panic("decryptHandshake: shouldn't reach here")
	} else if peer.initiator == false || peer.established == true {
		// This is a hello packet and we are either established or not the initiator
		//
		// If we are established, the peer reset the session and we haven't. So we need to reset
		// the session
		//
		// If we are not in established state, we disallow session resetting unless they
		// are the sender of the hello or their perm public key is lower.
		//
		// This is a tie breaker in case hello packets cross on the wire

		if peer.established {
			peer.resetSession()
		}

		// We received possible repeat hello packet but we haven't sent any hello packets
		if peer.nextNonce == 3 {
			// We have sent a key packet, but received another hello. Continue to send repeat key packets
			nextNonce = 3
		}

		peer.nextNonce = nextNonce
		peer.tempPublicKey = herTempPublicKey

	} else if bytes.Compare([]byte(peer.publicKey[:]), []byte(auth.keyPair.publicKey[:])) < 0 {
		// Received a hello packet and we are initiator, but their perm public key is numerically lower.
		// In this scenario, the node with the lower public key 'wins'. So if our public key is higher,
		// we will reset our session.
		peer.log.Debug("decryptHandshake: Incoming hello from node with lower key, resetting")
		peer.resetSession()
		peer.nextNonce = nextNonce
		peer.tempPublicKey = herTempPublicKey
	} else {
		// Since the peer has a higher public key, we don't reset our session. They should
		peer.log.Debug("decryptHandshake: Incoming hello from node with higher key, not resetting")
	}

	if isEmpty(handshake.PublicKey) == false && handshake.PublicKey != peer.publicKey {
		peer.publicKey = handshake.PublicKey
	}

	// TODO: Skipped condition where handshake was initiated in reverse and we have buffered messages -- FIXME

	// TODO: Test this condition
	if len(data) == CryptoHeader_MAXLEN {
		if handshake.Challenge.isSetupPacket() == 1 {
			return errNone
		}
	}

	peer.replayProtector = new(ReplayProtector)

	//passwordHash := peer.tryAuth(handshake, auth)

	//spew.Dump(peer)

	peer.log.Debugf("decryptHandshake: reached end, \n\tnonce = [%d]\n\tnextNonce = [%d]\n\tpeer.nextNonce = [%d]", nonce, nextNonce, peer.nextNonce)

	return errNone

	panic("i dont know what to do now!")
	return nil
}

func (peer *Peer) encryptHandshake(msg []byte, isSetup int, auth *CryptoAuth_Auth) ([]byte, *cjdnsError) {
	h := new(CryptoAuth_Handshake)
	h.Challenge = new(CryptoAuth_Challenge)
	//var passwordHash [32]byte

	peer.log.Debugf("encryptHandshake: stage is %d", peer.nextNonce)

	nonce := make([]byte, 24)
	rand.Read(nonce)
	copy(h.Nonce[:], nonce)

	h.PublicKey = auth.keyPair.publicKey
	// auth.keyPair.publicKey

	if peer.password != nil {
		panic("encryptHandshake: got here")
		//passwordHash, secondHash := hashPassword(peer.password, 1)
		//copy(peer.passwordHash[:], hashPassword(peer.password, 1))
		h.Challenge.Type = 1
	} else {
		h.Challenge.Type = 0
	}

	h.Challenge.setPacketAuthRequired(1)
	h.Challenge.setSetupPacket(0)

	h.Stage = peer.nextNonce

	//peer.tempKeyPair = createTempKeyPair()

	if peer.nextNonce == 0 || peer.nextNonce == 2 {
		if peer.tempKeyPair == nil {
			peer.log.Debug("you dont have a temp key pair")
			peer.tempKeyPair = createTempKeyPair()
		}
		//peer.tempKeyPair = createTempKeyPair()
		//h.tempPublicKey = peer.tempKeyPair.publicKey
	}

	if peer.nextNonce < 2 {
		peer.log.Debug("encryptHandshake: generating shared secret with peer publicKey for hello packet")
		peer.sharedSecret = computeSharedSecretWithPasswordHash(auth.keyPair.privateKey, peer.publicKey, peer.passwordHash)
		peer.initiator = true
		peer.nextNonce = 1
	} else {
		peer.log.Debugf("encryptHandshake: generating shared secret with peer tempPublicKey and pw hash for key packet [%x]", peer.passwordHash)
		//peer.sharedSecret = computeSharedSecretWithPasswordHash(auth.keyPair.privateKey, peer.publicKey, peer.passwordHash)

		//peer.sharedSecret = computeSharedSecretWithPasswordHash(auth.keyPair.privateKey, peer.tempPublicKey, peer.passwordHash)
		peer.sharedSecret = computeSharedSecret(auth.keyPair.privateKey, peer.tempPublicKey)
		peer.nextNonce = 3
	}

	// Key Packet
	if peer.nextNonce == 2 {
		peer.sharedSecret = computeSharedSecretWithPasswordHash(auth.keyPair.privateKey, peer.tempPublicKey, peer.passwordHash)
	}

	// TODO: I dont think I'm doing this entirely right... Investigate
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

	peer.log.Debugf("Encrypting handshake with:\n\tnonce [%x]\n\tsecret [%x]\n\tcipher [%x]\n",
		h.Nonce, peer.sharedSecret, authenticatorAndEncryptedTempPubKey)

	// peer.log.WithFields(log.Fields{
	// 	"nonce":  fmt.Sprintf("%x", h.Nonce),
	// 	"secret": fmt.Sprintf("%x", peer.sharedSecret),
	// 	"cipher": authenticatorAndEncryptedTempPubKey,
	// }).Debug("Encrypting handshake")

	//spew.Dump(buf.Bytes())

	return buf.Bytes(), errNone

}
