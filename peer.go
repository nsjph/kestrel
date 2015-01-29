package main

import (
	_ "encoding/hex"
	_ "fmt"
	_ "github.com/op/go-logging"
	"log"
	_ "net"
)

func (peer *Peer) dumpKeys() {

	log.Printf("myPublicKey=%x", peer.routerKeyPair.publicKey)
	log.Printf("herPublicKey=%x", peer.publicKey)
	log.Printf("passwordHash=%x", peer.passwordHash)
	log.Printf("outputSecret=%x", peer.sharedSecret)

}

// func (peer *Peer) sendMessage(msg []byte) {
// 	if peer.nextNonce < 4 {
// 		n, err := peer.conn.WriteToUDP(msg, peer.addr)
// 		checkFatal(err)
// 		peer.log.Debug("Peer.sendMessage(): wrote %d bytes to peer %s", n, peer.name)
// 	}
// }

func (peer *Peer) establishSession() {
	// Send Hello Packet
}
