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
