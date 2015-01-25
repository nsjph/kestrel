# CryptoAuth Protocol

## Introduction

CryptoAuth is the section of the cjdns protocol stack used for establishing and
communicating between peers across untrusted networks. This is a document to
describe the various parts of CryptoAuth and provide a rough guide for implementors.

### Notes to implementors

* There is not one single, universal packet type to cryptoauth, but several, dependant on the state of the connection between peers
* Everything sent across the wire is BigEndian. Remember to convert  

# Handshake Packets

A handshake packet is used when establishing an encrypted session between two peers.

A handshake has five states. These are canonically defined in cjdns/crypto/cryptoauth.h. Handshake packets include the state to enable the remote peer to understand what response is expected.

* (**0**) A new CryptoAuth session, has not sent or received anything
* (**1**) Sent a hello message, waiting for a reply
* (**2**) Received a hello message, sent a key message, waiting for the session to complete
* (**3**) Sent a hello message and received a key message but have not gotten a data message yet 
* (**4**) The handshake is successful and received at least one message


## 0. Connect to Me Packet

A connect to me packet is an uncommon state, where a remote peer knows your IP, but doesn't know your permanent public key. It's not clear when that state will occur, as modern cjdroute installations require(?) at minimum a host, port, password and public key to be present in the connectTo section of cjdroute.conf.

Since the remote peer doesn't know your permanent public key, it asks for it. 

### Packet Structure

## 1. Hello Packet (Sending)

The sending node is attempting to establish a cryptoauth session, and sends a handshake packet with the session state set to uint32(1) and their own permanent public key. 

The other fields in the Handshake packet structure should be random bytes. The only important fields are the session state and permanent public key. 

### Packet Structure

A hello packet (sending) uses the following structure:

                          1               2               3
          0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       0 |                    Session State (1) - uint32                 |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       4 |                                                               |
         +                                                               +
       8 |                         Random 36 bytes                       |
         +           (replacing challenge and handshake nonce)           +
      12 |                                                               |
         +                                                               +
      16 |                                                               |
         +                                                               +
      20 |                                                               |
         +                                                               +
      24 |                                                               |
         +                                                               +
      28 |                                                               |
         +                                                               +
      32 |                                                               |
         +                                                               +
      36 |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      40 |                                                               |
         +                                                               +
      44 |                                                               |
         +                                                               +
      48 |                                                               |
         +                                                               +
      52 |                                                               |
         +                     Permanent Public Key                      +
      56 |                       32 bytes / uint8                        |
         +                                                               +
      60 |                                                               |
         +                                                               +
      64 |                                                               |
         +                                                               +
      68 |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      72 |                                                               |
         +                                                               +
      76 |                                                               |
         +                      Random 48 bytes                          +
      80 |          (replaces authenticator and temp pub key)            |
         +                                                               +
      84 |                                                               |
         +                                                               +
      88 |                                                               |
         +                                                               +
      92 |                                                               |
         +                                                               +
      96 |                                                               |
         +                                                               +
     100 |                                                               |
         +                                                               +
     104 |                                                               |
         +                                                               +
     108 |                                                               |
         +                                                               +
     112 |                                                               |
         +                                                               +
     116 |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                                                               |
         +        Variable Length Encrypted/Authenticated Content        +
         |                                                               |


## 2. Hello Packet (Acknowledgement), Key Packet (Sending)

### Packet Structure 


## 3. Key Packet (Acknowledgement), Data Message not received

## 4. Handshake successful 

## 

# Data Packet

# Message Packet

# Handshakes

# References




