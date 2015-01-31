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
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/curve25519"
	_ "log"
	"net"
)

func createTempKeyPair() *KeyPair {

	keyPair := new(KeyPair)

	rand.Read(keyPair.privateKey[:32])

	//rand.Read(privateKey[:32])
	curve25519.ScalarBaseMult(&keyPair.publicKey, &keyPair.privateKey)
	//log.Printf("tempkeypair: pubkey = [%x]", keyPair.publicKey)
	//return publicKey, privateKey
	return keyPair
}

func privateKeyStringToPublicKey(privateKeyString string) [32]byte {
	d, _ := hex.DecodeString(privateKeyString)
	var privateKey [32]byte
	//privateKey = make([32]byte, 32)
	copy(privateKey[:32], d[:32])
	return createPublicKey(privateKey)
}

func publicKeyToBase32(key [32]uint8) string {
	return fmt.Sprintf("%s.k", base32Encode(key[:])[:52])
}

func keyToHex(key [32]byte) string {
	return hex.EncodeToString(key[:])
}

// For confirming that your converting between bits to hex and base32 correctly
func publicKeyStringToHex(keystring string) string {
	// decode from base32
	decoded, err := base32Decode([]byte(keystring))
	check(err)
	//fmt.Printf("decoded: %x\n", decoded)

	// encode to hex
	hexencoded := hex.EncodeToString(decoded)
	//fmt.Printf("hexencoded: %s\n", hexencoded)
	return hexencoded
}

func createPrivateKey() [32]byte {
	var key [32]byte
	rand.Read(key[:])
	return key
}

func createPublicKey(privateKey [32]byte) (publicKey [32]byte) {
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

func hashPublicKey(publicKey []byte) []byte {
	x := sha512.Sum512(publicKey[:])
	y := sha512.Sum512(x[:])
	return y[0:16]
}

func publicKeyToIPv6(publicKey []byte) net.IP {
	hashedKey := hashPublicKey(publicKey[:])
	return net.IP.To16(hashedKey)
}

func isValidIPv6(ip []byte) bool {

	if ip == nil {
		return false
	}

	if ip[0] == 0xFC {
		return true
	}
	return false
}

type CryptoKeys struct {
	PublicKey, PrivateKey [32]byte
	IPv6                  net.IP
}

func generateKeys() CryptoKeys {

	keys := CryptoKeys{}

	for isValidIPv6(keys.IPv6) != true {
		keys.PrivateKey = createPrivateKey()
		keys.PublicKey = createPublicKey(keys.PrivateKey)
		keys.IPv6 = publicKeyToIPv6(keys.PublicKey[:])
	}

	return keys
}
