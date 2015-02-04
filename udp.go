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
	"github.com/sirupsen/logrus"
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
	u.log = logrus.New()
	//u.log.
	u.log.Out = os.Stderr
	u.log.Level = logrus.DebugLevel

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

		n, oobn, _, _, err := u.conn.ReadMsgUDP(payload, oob)
		u.log.Debug("UDPServer.readLoop(): payload[%d], oob[%d]", n, oobn)
		checkFatal(err)

	}
}
