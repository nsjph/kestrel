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

package main

import (
	_ "bytes"
	_ "code.google.com/p/gopacket"
	_ "crypto/sha256"
	_ "encoding/binary"
	_ "encoding/hex"
	"github.com/op/go-logging"
	"log"
	"net"
	"os"
	"syscall"
)

const (
	UDP_MAX_PACKET_SIZE    = 8192
	UDP_PADDING            = 512
	UDP_MAX_PACKET_PAYLOAD = UDP_MAX_PACKET_SIZE - UDP_PADDING
)

func (c *ServerConfig) newUDPServer() *UDPServer {

	u := new(UDPServer)

	u.bufsz = UDP_MAX_PACKET_SIZE
	u.padsz = UDP_PADDING
	u.config = c
	u.log = initLogger("kestrel", logging.DEBUG, os.Stderr)
	u.keyPair = u.config.getServerKeyPair()
	u.accounts = make([]*Account, 100)
	//u.addAccount(c.Password, 1, nil)
	u.peers = make(map[string]*Peer)

	u.auth = new(CryptoAuth_Auth)
	u.auth.keyPair = u.config.getServerKeyPair()
	u.auth.accounts = make(map[[32]byte]*Account)
	//u.auth.accounts = make([]*Account, 100)
	u.auth.addAccount(c.Password, 1, nil)
	u.auth.log = initLogger("kestrel2", logging.DEBUG, os.Stderr)

	return u
}

func (u *UDPServer) start() {

	u.log.Debug("Starting UDP Interface on %s", u.config.Listen)
	u.listen()
}

func (u *UDPServer) listen() {

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

	u.log.Debug("UDPServer.listen(): going into read loop")
	go u.readLoop()
}
func (u *UDPServer) readLoop() {
	defer u.conn.Close()
	payload := make([]byte, u.bufsz) // TODO: optimize
	oob := make([]byte, 4096)        // TODO: optimize

	for {

		n, oobn, _, addr, err := u.conn.ReadMsgUDP(payload, oob)
		u.log.Debug("UDPServer.readLoop(): payload[%d], oob[%d]", n, oobn)
		checkFatal(err)

		peer, present := u.peers[addr.String()]
		if present == false {
			peer = u.newPeer(addr)
		}

		peer.receiveMessage(payload, u.auth)

		// Check if it is a handshake or data packet
		// stage := binary.BigEndian.Uint32(payload[:4])

		// if stage <= 4 {
		// 	u.log.Debug("UDPServer.readLoop(): received handshake packet, stage (%d)", stage)

		// 	// decode packet for debugging
		// 	p := gopacket.NewPacket(payload[:n], LayerTypeHandshake, gopacket.Lazy)
		// 	//u.log.Debug("inbound packet: %s", p.String())

		// 	h := new(Handshake)

		// 	if handshakeLayer := p.Layer(LayerTypeHandshake); handshakeLayer != nil {

		// 		h, _ = handshakeLayer.(*Handshake)

		// 		switch stage {
		// 		case 0:
		// 			peer.nextNonce = 0
		// 			u.log.Debug("received connect to me packet")
		// 		case 1:
		// 			u.log.Debug("remote peer sent a hello message, is waiting for reply")

		// 			peer.nextNonce = 1

		// 			peer.publicKey = h.PublicKey

		// 			peer.dumpKeys()

		// 			peer.sendHandshake(peer.encryptHandshake())
		// 			//msg := testMessage2()
		// 			//peer.sendMessage(msg)

		// 		case 2:
		// 			u.log.Debug("remote peer received a hello message, sent a key message, is waiting for the session to complete")
		// 		case 3:
		// 			u.log.Debug("Sent a hello message and received a key message but have not gotten a data message yet")
		// 		case 4:
		// 			u.log.Debug("The CryptoAuth session has successfully done a handshake and received at least one message")
		// 		}
		// 	}
		// }
	}
}

func (u *UDPServer) newPeer(addr *net.UDPAddr) *Peer {

	u.log.Debug("UDPServer.newPeer(): creating new peer")
	peer := new(Peer)

	peer.addr = addr
	peer.name = addr.String()
	peer.routerKeyPair = u.keyPair
	peer.replayProtector = new(ReplayProtector)
	peer.conn = u.conn
	peer.log = u.log
	peer.established = false

	// if we have their password, we'll use password auth to connect

	// XXXXtemporary disable

	// if []byte(u.config.Password) != nil {
	// 	peer.password = []byte(u.config.Password)
	// } else {
	// 	peer.password = nil
	// }

	// 	h1 := sha256.Sum256(peer.password)
	// 	//h2 := sha256.Sum256(h1[:32])
	// 	u.log.Debug("HASHBABY %x", hex.EncodeToString(h1[:]))
	// 	peer.passwordHash = h1
	// 	peer.tempKeyPair = createTempKeyPair()
	// } else { // we'll use poly1305 and need temporary keys
	// 	peer.tempKeyPair = createTempKeyPair()
	// }
	u.peers[peer.name] = peer

	return peer
}

// TODO: Decide if this is the right place for addAccount related functions

// TODO: move the auth initialization functions outside of udp.go, doesn't belong here

func (auth *CryptoAuth_Auth) addAccount(password string, authType int, username []byte) {
	auth.addAccountWithIPv6(password, authType, username, nil)
}

func (auth *CryptoAuth_Auth) addAccountWithIPv6(password string, authType int, username []byte, ipv6 *net.Addr) {
	passwordHash := hashPassword_256([]byte(password))

	account := auth.accounts[passwordHash]

	if account == nil {
		account = new(Account)
		log.Println("addAccountWithIPv6: account is nil")
		// TODO: make username something meaningful
		account.username = []byte("blah")
		account.restrictedToIPv6 = ipv6
		auth.accounts[passwordHash] = account
	} else {
		log.Println("addAccountWithIPv6: account already exists")
		return
	}

	return

	// for _, v := range auth.accounts {
	// 	//auth.log.Debug("i = %d", i)
	// 	if v == nil {
	// 		//auth.log.Debug("addAccountWithIPv6")
	// 		return
	// 	}
	// 	if v.secret == passwordHash {
	// 		auth.log.Warning("addAccountWithIPv6: account already exists")
	// 		return
	// 	}

	// 	if bytes.Compare(username, v.username) == 0 {
	// 		auth.log.Warning("addAccountWithIPv6: username already exists")
	// 		return
	// 	}

	// }

	// account := new(Account)

	// account.username = username
	// if ipv6 != nil {
	// 	account.restrictedToIPv6 = ipv6
	// 	// TODO: add check to validate the IPv6
	// 	//u.log.Warning("addAccountWithIPv6: invalid ipv6")
	// 	//return
	// } else {
	// 	account.restrictedToIPv6 = nil
	// }

	// auth.accounts = append(auth.accounts, account)
}
