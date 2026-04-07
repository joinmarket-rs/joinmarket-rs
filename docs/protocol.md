# joinmarket-rs — Wire Protocol Reference

## Transport

All messages are JSON envelopes terminated by `\r\n`:

```json
{"type": <integer>, "line": "<payload>"}
```

The `type` field is an integer discriminator. The `line` field carries the payload string.

## Envelope types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 685 | PRIVMSG | peer → DN → peer | Private message relay |
| 687 | PUBMSG | peer → DN → all | Public broadcast |
| 789 | PEERLIST | DN → peer | List of known makers |
| 791 | GETPEERLIST | peer → DN | Request maker list |
| 793 | HANDSHAKE | peer → DN | Initial handshake |
| 795 | DN_HANDSHAKE | DN → peer | Handshake response |
| 797 | PING | DN → peer | Liveness probe |
| 799 | PONG | peer → DN | Liveness response |
| 801 | DISCONNECT | either | Graceful close |

## Handshake

### Peer → DN (type 793)

```json
{
  "app-name": "joinmarket",
  "directory": false,
  "location-string": "abcdef1234567890.onion:5222",
  "proto-ver": 5,
  "features": {},
  "nick": "J5xhGSWE7VrxM7sO",
  "network": "mainnet"
}
```

- `location-string`: `"onion:port"` for makers, `""` or `"NOT-SERVING-ONION"` for takers
- `features` may contain `"fidelity_bond"` (base64-encoded 252-byte proof)

### DN → Peer (type 795)

```json
{
  "app-name": "joinmarket",
  "directory": true,
  "location-string": "abcdef1234567890.onion:5222",
  "proto-ver-min": 5,
  "proto-ver-max": 5,
  "features": {},
  "accepted": true,
  "nick": "J5dirNickOOOOOOO",
  "network": "mainnet",
  "motd": "Welcome to this directory node"
}
```

## GETPEERLIST / PEERLIST exchange (envelope types 791 / 789)

Peer sends an empty type 791 envelope. DN responds with type 789 containing comma-separated `nick;location` pairs:

```
→ {"type": 791, "line": ""}
← {"type": 789, "line": "J5dir;dir.onion:5222,J5maker;maker.onion:5222"}
```

Disconnected peers may be suffixed with `;D`. Only makers appear in the peer list — takers are never exposed.

## PING / PONG (envelope types 797 / 799)

DN sends type 797 to probe liveness after a peer has been idle for 10 minutes. Peer responds with type 799. Peers that do not respond within 30 seconds are evicted. Peers idle for 25 minutes are hard-evicted without a probe.

Python JoinMarket clients that do not support PING/PONG are probed differently: the DN sends them a unicast `!orderbook` PUBMSG, which prompts the maker to re-announce its offers. Receiving those offer pubmsgs updates the maker's idle timer. Non-ping takers receive no probe and are hard-evicted at 15 minutes if silent.

```
← {"type": 797, "line": ""}
→ {"type": 799, "line": ""}
```

## Application commands (`!` prefixed, inside PUBMSG / PRIVMSG payloads)

### Message format

PUBMSG payload: `<from_nick>!PUBLIC!<command> <fields...>`
PRIVMSG payload: `<from_nick>!<to_nick>!!<command> <fields...>`

Commands are `!`-prefixed, whitespace-delimited, newline-terminated. Maximum line length: 40,000 bytes (matches Python JoinMarket's `MAX_LENGTH`).

### Public broadcast commands (via PUBMSG type 687)

| Command | Purpose |
|---------|---------|
| `!absoffer` | Absolute fee offer announcement |
| `!reloffer` | Relative fee offer announcement |
| `!swabsoffer` | Segwit absolute fee offer |
| `!swreloffer` | Segwit relative fee offer |
| `!sw0absoffer` | Native segwit absolute fee offer |
| `!sw0reloffer` | Native segwit relative fee offer |
| `!orderbook` | Orderbook request/update |
| `!cancel` | Cancel an order by ID |
| `!hp2` | PoDLE commitment broadcast |
| `!tbond` | Fidelity bond proof announcement |

The DN broadcasts all recognised public commands to every connected peer via a single broadcast channel. Offer commands additionally update the sender's `last_ann` record in the makers registry (if the sender is a Maker). The sender never receives its own message back (echo filter applied).

### Private commands (via PRIVMSG type 685)

| Command | Purpose |
|---------|---------|
| `!fill` | Taker initiates coinjoin with a maker |
| `!pubkey` | Maker sends ephemeral encryption public key |
| `!auth` | Taker sends authentication / revelation |
| `!ioauth` | Maker sends input/output authorization |
| `!tx` | Encrypted transaction data |
| `!sig` | Encrypted transaction signatures |
| `!push` | Push completed transaction |
| `!error` | Error notification |
| `!hp2` | Commitment transfer (private) |

The DN relays PRIVMSG envelopes opaquely to the target peer without parsing the inner command. It also sends a PEERLIST (type 789) containing the sender's onion address to the target, enabling direct peer-to-peer connection.

## Private message routing

```
Taker sends PRIVMSG to DN:
  {"type": 685, "line": "J5taker!J5maker!!fill 1000000 ..."}

DN forwards PRIVMSG to maker:
  {"type": 685, "line": "J5taker!J5maker!!fill 1000000 ..."}

DN also sends PEERLIST with taker's location to maker:
  {"type": 789, "line": "J5taker;taker.onion:5222,J5dir;dir.onion:5222"}

Maker can then connect directly to taker.onion:5222 for subsequent negotiation.
```
