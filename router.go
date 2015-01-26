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
	"encoding/binary"
	"encoding/hex"
	"github.com/nsjph/tun"
	"github.com/op/go-logging"
	"net"
	"os"
	"syscall"
)

func newRouter(c *TomlConfig) *Router {

	router := &Router{Config: &c.Server,
		BufSz: 1500,
		Log:   initLogger("kestrel", logging.DEBUG, os.Stderr),
		Peers: make(map[string]*Peer)}

	router.Log.Debug(router.Config.PublicKey[:50])

	pubkey, err := base32Decode([]byte(router.Config.PublicKey[:52]))
	checkFatal(err)
	copy(router.PublicKey[:], pubkey[:32])

	_, err = hex.Decode(router.PrivateKey[:], []byte(router.Config.PrivateKey))
	checkFatal(err)

	return router
}

func (router *Router) Start() {

	router.Log.Debug("starting")
	router.Iface = router.startTunDevice(router.Config.IPv6)
	router.UDPConn = router.listenUDP(router.Config.Listen)
}

func (router *Router) startTunDevice(ipv6addr string) *tun.Tun {

	router.Log.Debug("starting tun device")

	tunDevice := tun.New()
	tunDevice.Open()
	tunDevice.SetupAddress(ipv6addr, int(1312))
	tunDevice.Start()

	return tunDevice
}

func (router *Router) listenUDP(listenAddress string) *net.UDPConn {

	router.Log.Debug("starting udp listener on %s", listenAddress)

	localAddr, err := net.ResolveUDPAddr("udp4", listenAddress)

	checkFatal(err)
	conn, err := net.ListenUDP("udp4", localAddr)
	checkFatal(err)
	f, err := conn.File()
	defer f.Close()
	checkFatal(err)
	fd := int(f.Fd())
	// This one makes sure all packets we send out do not have DF set on them.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	checkFatal(err)

	router.Log.Debug("udp listener going into read loop")

	go router.udpReader(conn)
	return conn
}
func (router *Router) udpReader(conn *net.UDPConn) {
	defer conn.Close()
	payload := make([]byte, 4096) // TODO: optimize
	oob := make([]byte, 4096)     // TODO: optimize

	for {

		n, oobn, _, addr, err := conn.ReadMsgUDP(payload, oob)
		router.Log.Debug("payload[%d], oob[%d]", n, oobn)
		checkFatal(err)

		// Create or update peer map entry
		peerName := addr.String()
		router.Log.Debug("remote peer addr is %s\n", peerName)
		peer, present := router.Peers[peerName]
		if present == false {
			router.Log.Debug("new remote peer")
			peer = &Peer{addr: addr, name: peerName, password: nil}
			router.Peers[peerName] = peer
		} else {
			router.Log.Debug("peer already known")
		}

		// Check if it is a handshake or data packet
		nonce := binary.BigEndian.Uint32(payload[:4])

		if nonce <= 4 {

			p := gopacket.NewPacket(payload[:n], LayerTypeHandshake, gopacket.Lazy)
			router.Log.Debug("inbound packet: %s", p.String())

			var h *Handshake

			if handshakeLayer := p.Layer(LayerTypeHandshake); handshakeLayer != nil {
				// router.Log.Debug("This is a handshake packet!")
				h, _ = handshakeLayer.(*Handshake)
				// router.Log.Debug("handshake stage: %d", h.Stage)
				router.Log.Debug("received handshake packet with nonce: %x", h.Nonce)
			}

			switch nonce {
			case 0:
				peer.nextNonce = 0
				router.Log.Debug("received connect to me packet")
			case 1:
				router.Log.Debug("remote peer sent a hello message, is waiting for reply")

				//router.Log.Debug("")

				peer.nextNonce = 1
				peer.publicKey = h.PublicKey
				//msg := testMessage()
				msg := testMessage2()
				//msg := newMessage(0, 512)
				router.sendMessage(msg, peer)

				// TODO: When/where is the best place to update the peer map entry?
				router.Peers[peerName] = peer
			case 2:
				router.Log.Debug("remote peer received a hello message, sent a key message, is waiting for the session to complete")
			case 3:
				router.Log.Debug("Sent a hello message and received a key message but have not gotten a data message yet")
			case 4:
				router.Log.Debug("The CryptoAuth session has successfully done a handshake and received at least one message")
			}
		}

		// Before we finish, update the peer map entry
		router.Peers[peerName] = peer

	}
}
