package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"github.com/nsjph/tun"
	"github.com/op/go-logging"
	"net"
	"time"
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

// type CryptoAuth struct {
// }

// type TCPHeader struct {
// 	Source      uint16
// 	Destination uint16
// 	SeqNum      uint32
// 	AckNum      uint32
// 	DataOffset  uint8 // 4 bits
// 	Reserved    uint8 // 3 bits
// 	ECN         uint8 // 3 bits
// 	Ctrl        uint8 // 6 bits
// 	Window      uint16
// 	Checksum    uint16 // Kernel will set this if it's 0
// 	Urgent      uint16
// 	Options     []TCPOption
// }

// type CryptoAuthHeader struct {
// 	State         uint8
// 	Challenge     [3]byte
// 	Nonce         [6]byte
// 	PermPublicKey [8]byte
// 	Authenticator [4]byte
// 	TempPublicKey [8]byte
// 	Content       []byte
// }

// type CryptoAuthHeader struct {
// 	State         uint8
// 	Challenge     [3]uint8
// 	Nonce         [6]uint8
// 	PermPublicKey [8]uint8
// 	Authenticator [4]uint8 // shared secret?
// 	TempPublicKey [8]uint8
// }

// type CryptoAuthPacket struct {
// 	Header CryptoAuthHeader
// }

// type CryptoAuthChallengeHeader struct {
// 	Type   uint8
// 	Lookup [7]uint8
// }

// type CryptoAuthType struct {
// }

// type CryptoAuthHeader1 struct {
// 	State         uint32
// 	Challenge     uint64
// 	Nonce         [24]uint8
// 	PermPublicKey [32]uint8
// 	Authenticator [16]uint8
// 	TempPublicKey [32]uint8
// 	Content       []byte
// }

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

// type PeerKeys struct {
// 	publicKey    [32]byte
// 	sharedSecret [32]byte
// 	password     []byte
// 	tempKeyPair  *KeyPair
// }

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
	passwordHash  []byte
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

type PeerName string

type UDPPacket struct {
	Name   PeerName
	Packet []byte
	Sender *net.UDPAddr
}

type UDPSender interface {
	Send([]byte) error
	Shutdown() error
}

type Connection interface {
	Local() *Peer
	Remote() *Peer
	RemoteTCPAddr() string
	Established() bool
	Shutdown()
}

type ForwardedFrame struct {
	srcPeer *Peer
	dstPeer *Peer
	frame   []byte
}

// type Peer struct {
// 	sync.RWMutex
// 	Name          PeerName
// 	NameByte      []byte
// 	UID           uint64
// 	version       uint64
// 	localRefCount uint64
// 	connections   map[PeerName]Connection
// }

type RemoteConnection struct {
	local         *Peer
	remote        *Peer
	remoteTCPAddr string
}

type LocalConnection struct {
	remoteUDPAddr *net.UDPAddr
	established   bool
	stackFrag     bool
	effectivePMTU int
	SessionKey    *[32]byte
	heartbeat     *time.Ticker
	fetchAll      *time.Ticker
	fragTest      *time.Ticker
	forwardChan   chan<- *ForwardedFrame
	forwardChanDF chan<- *ForwardedFrame
	stopForward   chan<- interface{}
	stopForwardDF chan<- interface{}
	verifyPMTU    chan<- int
	//Decryptor     Decryptor
	Router   *Router
	UID      uint64
	shutdown bool
	//queryChan chan<- *ConnectionInteraction
}

type SimpleUDPSender struct {
	conn    *LocalConnection
	udpConn *net.UDPConn
}
type RawUDPSender struct {
	ipBuf     gopacket.SerializeBuffer
	opts      gopacket.SerializeOptions
	udpHeader *layers.UDP
	socket    *net.IPConn
	conn      *LocalConnection
}

type PacketSource interface {
	ReadPacket() ([]byte, error)
}
type PacketSink interface {
	WritePacket([]byte) error
}
type PacketSourceSink interface {
	PacketSource
	PacketSink
}
