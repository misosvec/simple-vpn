# Simple Golang VPN
*Note: not yet fully completed*

This repository contains a lightweight VPN experiment written in Go. It demonstrates a UDP-based, event-driven system with a custom handshake, virtual IP allocation, and TUN interface integration to route client traffic securely through the VPN.

The primary goal of this project was to become somewhat familiar with:
- Go
- Goroutines and channels
- Concurrency patterns
- Low-level networking concepts (TUN devices, UDP, NAT, encryption)

## Components

Both the client and server require Linux, as they rely on Linux-specific networking primitives. Each component, `client` and `server`, is provided with its own `Dockerfile`, while additional configuration is defined in the `compose.yaml` file.

- `server/` — Server binary and logic (client manager, IP pool, UDP listener, packet routing)
- `client/` — Client binary that connects to the server, performs the handshake, and routes traffic through the VPN
- `common/` — Shared utilities (packet formats, cryptographic helpers, TUN setup, networking helpers)

## How it works

### Server

- Creates a TUN interface and assigns it an IP address  
- Starts a UDP server to accept incoming client connections  
- Performs a handshake with clients to establish secure communication  
- Maintains a pool of available virtual IP addresses  
- Decrypts incoming client traffic and forwards it to its destination  
- Encrypts responses and sends them back to the client  
- Releases allocated resources when a client becomes inactive

###  Client

- Creates a TUN interface  
- Configures routing to direct traffic through the TUN device  
- Opens a UDP socket and initiates a handshake with the server  
- Captures outgoing traffic from the TUN interface, encrypts it, and sends it to the VPN server  
- Receives traffic from the VPN server, decrypts it, and forwards it to the local system  

## Handshake

1. **Client → Server**
   - Sends a `KeyExchangePacket` containing its public key

2. **Server → Client**
   - Responds with its own `KeyExchangePacket` (server public key)

3. **Key Derivation**
   - Both sides compute a shared secret using ECDH (X25519)

4. **Server → Client**
   - Allocates a virtual IP from the IP pool
   - Stores mapping:
     ```
     real UDP addr (IP:port) ↔ virtual IP (e.g. 12.0.0.x)
     ```
   - Sends a `VirtualIPPacket` (encrypted with the shared key)

5. **Client → Server**
   - Sets the received virtual IP
   - Sends a `ClientReadyPacket` to confirm the handshake is complete

6. **Connection Established**
   - The client is now registered as active and can exchange encrypted traffic with the server

## Traffic Flow

### Client → Server → Network

1. Client captures outgoing packets via its TUN interface
2. Wraps them in a custom `TrafficPacket`
3. Encrypts using the shared key (AEAD)
4. Sends over UDP to the server
5. Server:
   - Receives UDP packet
   - Decrypts and validates it
   - Writes the inner IP packet to its TUN interface
6. The OS processes and routes the packet


### Network → Server → Client

1. Incoming packets are routed by the OS to the server’s TUN interface
2. Server reads packets from TUN
3. Determines destination client based on virtual IP
4. Encrypts the packet
5. Sends it via UDP to the appropriate client
6. Client:
   - Receives UDP packet
   - Decrypts it
   - Writes it to its TUN interface
   - OS processes it as normal network traffic


## Key Design Concepts

- **TUN Interface**: Acts as a virtual network device for injecting and receiving raw IP packets
- **UDP Transport**: Lightweight, connectionless communication between client and server
- **ECDH Key Exchange**: Establishes a shared secret without transmitting it directly
- **AEAD Encryption**: Ensures confidentiality and integrity of packets
- **NAT (MASQUERADE)**: Allows VPN clients to access external networks via the server
- **Concurrency Model**:
  - Goroutines for parallel processing
  - Channels for communication between components
  - Worker pools for handling packet processing efficiently


## How to run

### Run the server

#### 1. Build the server image

```bash
docker compose build vpn-server
```

#### 2. Start the server

```bash
docker compose up vpn-server
```


### Run the client

#### 1. Build the client image

```bash
docker compose build vpn-client
```

#### 2. Start the client

```bash
docker compose up vpn-client
```

#### 3. Test the connection

##### Enter the client container

```bash
docker compose exec vpn-client bash
```

##### Verify internet connectivity

```bash
ping -c 3 8.8.8.8
```
