package main

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"fmt"
	"log"
)

type Handshake struct {
	layers.BaseLayer
	Stage uint32
	//Challenge     CryptoAuth_Challenge
	Challenge     CryptoAuth_Challenge // We use a generic container initially then decode it into appropriate struct later
	Nonce         [24]uint8            // 24 bytes
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
	//h := new(CryptoAuth_Handshake)
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
	binary.Read(r, binary.BigEndian, &h.Challenge.Type)
	binary.Read(r, binary.BigEndian, &h.Challenge.Lookup)
	binary.Read(r, binary.BigEndian, &h.Challenge.RequirePacketAuthAndDerivationCount)
	binary.Read(r, binary.BigEndian, &h.Challenge.Additional)
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
