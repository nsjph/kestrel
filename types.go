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

type Account struct {
	username         []byte
	secret           [32]byte
	restrictedToIPv6 *net.Addr
}

// TODO: Move the server-side credentials away from the *Peer
// particularly the accounts
type CryptoAuth_Auth struct {
	accounts []*Account
	keyPair  *KeyPair
	log      *logging.Logger // go-logging
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
	conn     *net.UDPConn
	keyPair  *KeyPair
	config   *ServerConfig
	bufsz    int
	padsz    int
	log      *logging.Logger // go-logging
	peers    map[string]*Peer
	accounts []*Account
	auth     *CryptoAuth_Auth
}

type InterfaceController struct {
	ifaces []*UDPServer
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
	name string
	addr *net.UDPAddr
	conn *net.UDPConn
	//server        *UDPServer
	password        []byte // static password for incoming / outgoing peers..?
	state           uint32 // handshake state or nonce
	nextNonce       uint32
	tempKeyPair     *KeyPair // This is our tempKeyPair, not actually the peers
	routerKeyPair   *KeyPair
	sharedSecret    [32]byte
	publicKey       [32]byte
	tempPublicKey   [32]byte // This is the remote peer's temporary public key
	log             *logging.Logger
	passwordHash    [32]byte
	initiator       bool
	established     bool
	requireAuth     bool
	replayProtector *ReplayProtector
}

type ReplayProtector struct {
	bitfield           uint64
	baseOffset         uint32
	duplicates         uint32
	lostPackets        uint32
	receivedOutOfRange uint32
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
