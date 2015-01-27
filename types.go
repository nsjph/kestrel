package main

import (
	"github.com/nsjph/tun"
	"github.com/op/go-logging"
	"net"
)

type ServerInfo struct {
	//Conn      *net.UDPConn
	Server    *UDPServer
	TunDevice *tun.Tun
	Peers     []PeerInfo
}

type PeerInfo struct {
	PublicAddress *net.IPAddr
	CjdnsAddress  *net.IPAddr
	Conn          *net.UDPConn
	Password      []byte
	PublicKey     []byte
	SharedKey     []byte
}

type TomlConfig struct {
	Server ServerConfig
}

type ServerConfig struct {
	Listen     string `toml:"listen"`
	Device     string `toml:"device"`
	PublicKey  string `toml:"public_key"`
	PrivateKey string `toml:"private_key"`
	IPv6       string `toml:"ipv6"`
	Password   string `toml:"password"`
}

type UDPServer struct {
	Conn *net.UDPConn
}

//type Server struct

type UDPInterface struct {
	conn    *net.UDPConn
	keyPair *KeyPair
	config  *ServerConfig
	bufsz   int
	padsz   int
	log     *logging.Logger // go-logging
	peers   map[string]*Peer
}

type InterfaceController struct {
	ifaces []*UDPInterface
}

type Router struct {
	Iface      *tun.Tun
	PublicKey  [32]byte
	PrivateKey [32]byte
	UDPConn    *net.UDPConn
	Config     *ServerConfig
	BufSz      int
	Log        *logging.Logger // go-logging
	Peers3     map[string]*Peer
	Peers      map[[32]byte]*Peer
	keyPair    *KeyPair
}

type Passwd struct {
	user      [32]byte    // username string, max 32 bytes
	password  [32]byte    // hashed form of password loaded from kestrel.toml
	publicKey []byte      // future use - allow only a given public key to use this password
	addr      *net.IPAddr // future use - allow on a given remote ip addr to use this password
}

// TODO: Keep this?
type PublicKey [32]uint8

type KeyPair struct {
	publicKey  [32]byte
	privateKey [32]byte
}

type Peer struct {
	addr *net.UDPAddr
	conn *net.UDPConn
	name string // ip:port
	//tempPublicKey  [32]byte
	//tempPrivateKey [32]byte
	//sharedKey      [32]byte
	password      []byte // static password for incoming / outgoing peers..?
	state         uint32 // handshake state or nonce
	nextNonce     uint32
	tempKeyPair   *KeyPair
	routerKeyPair *KeyPair
	sharedSecret  [32]byte
	publicKey     [32]byte
	log           *logging.Logger
	passwordHash  [32]byte
	initiator     bool
}

type Message struct {
	length   uint32
	padding  uint32
	payload  []byte
	capacity uint32
}

type EncryptedMessage2 struct {
	handshake [120]byte
	payload   []byte
}
