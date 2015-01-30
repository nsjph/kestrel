package main

import (
	"encoding/binary"
)

type CryptoAuthChallenge struct {
	Type                                uint8
	Lookup                              [7]byte
	RequirePacketAuthAndDerivationCount uint16
	Additional                          uint16
}

type CryptoAuthHandshake struct {
	Stage uint32
	//	Challenge *CryptoAuthChallenge // We use a generic container initially then decode it into appropriate struct later
	Challenge []byte // 12 bytes
	Nonce     []byte // 24 bytes
	PublicKey []byte // 32
	//AuthenticatorAndencryptedTempPubKey []byte
	Authenticator []byte // 16 bytes
	TempPublicKey []byte // 32 bytes
	Payload       []byte
}

// For MessageType Interface
func (h *CryptoAuthHandshake) Protocol() int {
	return CRYPTOAUTH_HANDSHAKE_PACKET
}

// For MessageBody Interface
func (h *CryptoAuthHandshake) Len() int {
	return 120
}

// For MessageBody Interface
func (h *CryptoAuthHandshake) Marshal(protocol int) ([]byte, error) {
	return nil, nil
}

func parseCryptoAuthChallengeHeader(data []byte) (*CryptoAuthChallenge, error) {
	return nil, nil
}

// Just returns the 12 bytes representing the Challenge header
func parseCryptoAuthChallengeHeaderAsBytes(data []byte) ([]byte, error) {
	return nil, nil
}

func parseCryptoAuthHandshake(data []byte) (*CryptoAuthHandshake, error) {

	h := &CryptoAuthHandshake{
		Stage:         binary.BigEndian.Uint32(data[0:4]),
		Challenge:     data[4:16],
		Nonce:         data[16:40],
		PublicKey:     data[40:72],
		Authenticator: data[72:88],
		TempPublicKey: data[88:120],
	}

	return h, nil

	// h := new(CryptoAuth_Handshake)
	// h.Challenge = new(CryptoAuth_Challenge)

	// // h.buffer = h.buffer[:0]

	// if len(data) < 120 {
	// 	return nil, fmt.Errorf("CryptoAuthHandshake header too short")
	// }

	// r := bytes.NewReader(data)
	// binary.Read(r, binary.BigEndian, &h.Stage)
	// binary.Read(r, binary.BigEndian, &h.Challenge.Type)
	// binary.Read(r, binary.BigEndian, &h.Challenge.Lookup)
	// binary.Read(r, binary.BigEndian, &h.Challenge.RequirePacketAuthAndDerivationCount)
	// binary.Read(r, binary.BigEndian, &h.Challenge.Additional)
	// binary.Read(r, binary.BigEndian, &h.Nonce)
	// binary.Read(r, binary.BigEndian, &h.PublicKey)
	// binary.Read(r, binary.BigEndian, &h.Authenticator)
	// binary.Read(r, binary.BigEndian, &h.TempPublicKey)
	// //binary.Read(r, binary.BigEndian, &h.AuthenticatorAndencryptedTempPubKey)
	// return h, nil
}
