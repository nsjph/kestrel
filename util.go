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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// http://www.barrgroup.com/Embedded-Systems/How-To/Big-Endian-Little-Endian

func bufReadUint32(buf *bytes.Buffer) (uint32, error) {
	var numBuf [4]byte
	_, err := io.ReadFull(buf, numBuf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(numBuf[:]), nil
}
func bufWriteUint32(buf *bytes.Buffer, num uint32) {
	var numBuf [4]byte
	binary.BigEndian.PutUint32(numBuf[:], num)
	buf.Write(numBuf[:])
}

func checkFatal(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
func checkWarn(e error) {
	if e != nil {
		log.Println(e)
	}
}
func PosixError(err error) error {
	if err == nil {
		return nil
	}
	operr, ok := err.(*net.OpError)
	if !ok {
		return nil
	}
	return operr.Err
}

// func (mtbe MsgTooBigError) Error() string {
// 	return fmt.Sprint("Msg too big error. PMTU is ", mtbe.PMTU)
// }
// func (ftbe FrameTooBigError) Error() string {
// 	return fmt.Sprint("Frame too big error. Effective PMTU is ", ftbe.EPMTU)
// }
// func (upe UnknownPeersError) Error() string {
// 	return fmt.Sprint("Reference to unknown peers")
// }
// func (nce NameCollisionError) Error() string {
// 	return fmt.Sprint("Multiple peers found with same name: ", nce.Name)
// }
// func (pde PacketDecodingError) Error() string {
// 	return fmt.Sprint("Failed to decode packet: ", pde.Desc)
// }
func (packet UDPPacket) String() string {
	return fmt.Sprintf("UDP Packet\n name: %s\n sender: %v\n payload: % X", packet.Name, packet.Sender, packet.Packet)
}
func Concat(elems ...[]byte) []byte {
	res := []byte{}
	for _, e := range elems {
		res = append(res, e...)
	}
	return res
}
func randUint64() (r uint64) {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	checkFatal(err)
	for _, v := range buf {
		r <<= 8
		r |= uint64(v)
	}
	return
}
func macint(mac net.HardwareAddr) (r uint64) {
	for _, b := range mac {
		r <<= 8
		r |= uint64(b)
	}
	return
}
func intmac(key uint64) (r net.HardwareAddr) {
	r = make([]byte, 6)
	for i := 5; i >= 0; i-- {
		r[i] = byte(key)
		key >>= 8
	}
	return
}

type ListOfPeers []*Peer

func (lop ListOfPeers) Len() int {
	return len(lop)
}
func (lop ListOfPeers) Swap(i, j int) {
	lop[i], lop[j] = lop[j], lop[i]
}

// func (lop ListOfPeers) Less(i, j int) bool {
// 	return lop[i].Name < lop[j].Name
// }

// given an address like '1.2.3.4:567', return the address if it has a port,
// otherwise return the address with weave's standard port number
func NormalisePeerAddr(peerAddr string) string {
	_, _, err := net.SplitHostPort(peerAddr)
	if err == nil {
		return peerAddr
	} else {
		return fmt.Sprintf("%s:%d", peerAddr, Port)
	}
}
