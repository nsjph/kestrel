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
	_ "bytes"
	_ "code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	_ "code.google.com/p/gopacket/pcap"
	_ "encoding/binary"
	_ "fmt"
	"github.com/jphackworth/kestrel/tun"
	"github.com/op/go-logging"
	_ "github.com/vishvananda/netlink"
	_ "io"
	"log"
	_ "log"
	"net"
	"os"
	"syscall"
	_ "time"
)

// From cjdns/interface/UDPInterface_pvt.h
// const (
// 	UDP_PACKET_BUFSIZE = 512
// 	UDP_PACKET_MAXSIZE = 8192
// 	MSG_MAXSIZE        = UDP_PACKET_BUFSIZE + UDP_PACKET_MAXSIZE
// 	IFACE_BUFSIZE      = 2000
// )

// type Server struct {
// 	localConn *net.UDPConn
// 	peers     []Peer
// }

//https://stackoverflow.com/questions/21968266/handling-read-write-udp-connection-in-go
//http://golang.org/src/net/dnsclient_unix.go
// http://www.darkcoding.net/uncategorized/raw-sockets-in-go-ip-layer/

// func startUDPServer(listenAddress string) *net.UDPConn {

// 	addr, err := net.ResolveUDPAddr("udp4", listenAddress)
// 	check(err)

// 	conn, err := net.ListenUDP("udp4", addr)
// 	check(err)

// 	return conn
// }

// func startUDPServer(listenAddress string) *UDPServer {

// 	addr, err := net.ResolveUDPAddr("udp4", listenAddress)
// 	check(err)

// 	conn, err := net.ListenUDP("udp4", addr)
// 	check(err)

// 	return &UDPServer{conn}
// }

// type Router struct {
// 	Iface       *tun.Tun
// 	UDPListener *net.UDPConn
// }

func newRouter(c *TomlConfig) *Router {

	router := &Router{Config: &c.Server,
		BufSz: 1500,
		Log:   initLogger("kestrel", logging.DEBUG, os.Stderr)}

	//router.Log.SetBackend(&router.LogBackend)

	//router.UDPListener = listenUDP(c.Server.Listen)

	return router
}

func (router *Router) Start() {

	router.Log.Debug("starting")
	router.Iface = router.startTunDevice(router.Config.IPv6)
	router.UDPListener = router.listenUDP(router.Config.Listen)
}

func (router *Router) startTunDevice(ipv6addr string) *tun.Tun {

	router.Log.Debug("starting tun device")

	//log.Printf("starting tun device")

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
	buf := make([]byte, 4096)

	for {

		//router.Log.Debug("reading from UDP")

		numRead, _, err := conn.ReadFromUDP(buf)
		//conn.ReadFrom
		checkFatal(err)

		tca := NewCryptoAuth(buf[:numRead])
		//log.Printf("Nonce: %d, Handshake stage: %d, Challenge type: %d\n",
		//	tca.Nonce, tca.Handshake.Stage, tca.Handshake.Challenge.Type)
		//log.Println(tca)
		//log.Printf("PublicKey: %s.k", base32Encode(tca.Handshake.PublicKey[:])[:52])
		//log.Println(tca.Handshake.Challenge.String())
		//tca.Handshake.Challenge.Dump()
		log.Println(tca.Nonce)
		tca.Handshake.Dump()
		//PrintChallenge()
	}
}

//func (router *Router) sendMessage()

func (router *Router) handleUDPPacketFunc(po PacketSink) {

}
