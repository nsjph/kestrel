// Copyright 2014 JPH <jph@hackworth.be>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// router.go - formerly udp.go

package main

import (
	"code.google.com/p/gopacket"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/op/go-logging"
	"net"
	"os"
	"syscall"
)

const (
	UDPInterface_MAX_PACKET_SIZE = 8192
	UDPInterface_PADDING         = 512
)

func (c *ServerConfig) newUDPInterface() *UDPInterface {

	u := new(UDPInterface)

	u.bufsz = UDPInterface_MAX_PACKET_SIZE
	u.config = c
	u.log = initLogger("kestrel", logging.DEBUG, os.Stderr)
	u.keyPair = new(KeyPair)
	u.peers = make(map[[32]byte]*Peer)

	return u
}

func (u *UDPInterface) start() {

	u.log.Debug("Starting UDP Interface on %s", u.config.Listen)
	u.listen()
}

func (u *UDPInterface) listen() {

	//router.Log.Debug("starting udp listener on %s", listenAddress)

	localAddr, err := net.ResolveUDPAddr("udp4", u.config.Listen)
	checkFatal(err)

	u.conn, err = net.ListenUDP("udp4", localAddr)
	checkFatal(err)

	f, err := u.conn.File()
	defer f.Close()
	checkFatal(err)
	fd := int(f.Fd())
	// This one makes sure all packets we send out do not have DF set on them.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	checkFatal(err)

	u.log.Debug("UDPInterface.listen(): going into read loop")

	go u.readLoop()

}
func (u *UDPInterface) readLoop() {
	defer u.conn.Close()
	payload := make([]byte, u.bufsz) // TODO: optimize
	oob := make([]byte, 4096)        // TODO: optimize

	for {

		n, oobn, _, addr, err := u.conn.ReadMsgUDP(payload, oob)
		u.log.Debug("UDPInterface.readLoop(): payload[%d], oob[%d]", n, oobn)
		checkFatal(err)

		// Check if it is a handshake or data packet
		stage := binary.BigEndian.Uint32(payload[:4])

		if stage <= 4 {
			u.log.Debug("UDPInterface.readLoop(): received handshake packet, stage (%d)", stage)

			// decode packet for debugging
			p := gopacket.NewPacket(payload[:n], LayerTypeHandshake, gopacket.Lazy)
			u.log.Debug("inbound packet: %s", p.String())

			h := new(Handshake)

			if handshakeLayer := p.Layer(LayerTypeHandshake); handshakeLayer != nil {

				h, _ = handshakeLayer.(*Handshake)

				peer, present := u.peers[h.PublicKey]
				if present == false {
					peer = u.newPeer(h.PublicKey)
					peer.addr = addr
					peer.name = addr.String()

				}

				//peer.dumpKeys()

				switch stage {
				case 0:
					peer.nextNonce = 0
					u.log.Debug("received connect to me packet")
				case 1:
					u.log.Debug("remote peer sent a hello message, is waiting for reply")

					//router.Log.Debug("")

					peer.nextNonce = 1
					peer.publicKey = h.PublicKey
					//msg := testMessage()
					msg := testMessage2()
					//msg := newMessage(0, 512)
					peer.sendMessage(msg)

					// TODO: When/where is the best place to update the peer map entry?
					//router.Peers[peerName] = peer
				case 2:
					u.log.Debug("remote peer received a hello message, sent a key message, is waiting for the session to complete")
				case 3:
					u.log.Debug("Sent a hello message and received a key message but have not gotten a data message yet")
				case 4:
					u.log.Debug("The CryptoAuth session has successfully done a handshake and received at least one message")
				}
			}

		}

		// Before we finish, update the peer map entry
		//router.Peers[peerName] = peer

	}
}

func (u *UDPInterface) newPeer(publicKey [32]byte) *Peer {

	u.log.Debug("UDPInterface.newPeer(): creating new peer")
	peer := new(Peer)

	peer.publicKey = publicKey
	peer.routerKeyPair = u.keyPair
	peer.conn = u.conn
	peer.log = u.log

	// if we have their password, we'll use password auth to connect
	if []byte(u.config.Password) != nil {
		//c := sha256.New()

		peer.password = []byte(u.config.Password)
		h1 := sha256.Sum256(peer.password)
		//h2 := sha256.Sum256(h1[:32])
		u.log.Debug("HASHBABY %x", hex.EncodeToString(h1[:]))
		peer.passwordHash = h1
		peer.tempKeyPair = createTempKeyPair()
	} else { // we'll use poly1305 and need temporary keys
		peer.tempKeyPair = createTempKeyPair()
	}
	u.peers[publicKey] = peer

	return peer
}
