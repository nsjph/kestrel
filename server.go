package main

import (
	"encoding/hex"
	"github.com/nsjph/cryptoauth"
	"log"
	"os"
)

// func startServer(c TomlConfig) *ServerInfo {
// 	s := &ServerInfo{Server: startUDPServer(c.Server.Listen),
// 		TunDevice: startTunDevice(c)}

// 	return s
// }

func (s *ServerInfo) Shutdown() {
	log.Printf("shutting down")
	os.Exit(0)
}

func (c *ServerConfig) getServerKeyPair() *KeyPair {

	kp := &KeyPair{}

	pubkey, err := cryptoauth.Base32Decode([]byte(c.PublicKey[:52]))
	check(err)
	copy(kp.publicKey[:], pubkey[:32])

	_, err = hex.Decode(kp.privateKey[:], []byte(c.PrivateKey))
	check(err)

	return kp

}
