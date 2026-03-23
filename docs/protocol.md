# joinmarket-rs — Wire Protocol Reference

## Handshake (JSON, sent immediately on connect, both directions)

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

Directory node adds `"directory": true` and `"motd": "<message>"` to its outbound handshake.

## Message format

```
!command field1 field2 ... fieldN\n
```

Messages are newline-terminated (`\n`), whitespace-delimited. Maximum line length: 40,000 bytes (matches Python JoinMarket's `MAX_LENGTH`).

## `!getpeers` / `!peers` exchange

```
→ !getpeers\n
← !peers {"peers":[{"nick":"J5abc...","onion":"xxx.onion:5222","bond":null},...], "total_makers":42, "returned":42}\n
```

## Private message routing

```
→ !fill J5targetNick 1000000 ...\n
← !peerinfo J5targetNick abcdef.onion:5222\n
```

Taker then opens a direct circuit to `abcdef.onion:5222`. The directory node does NOT relay private message content.

## Heartbeat

```
← !ping\n
→ !pong\n
```

Directory sends `!ping` to all peers every 60 seconds. Peers that do not respond with `!pong` within 10 seconds are evicted.

## Supported commands

| Command      | Direction         | Purpose                              |
|--------------|-------------------|--------------------------------------|
| `!ann`       | peer → directory  | Public maker announcement (broadcast)|
| `!orderbook` | peer → directory  | Public orderbook update (broadcast)  |
| `!fill`      | taker → directory | Private routing request              |
| `!absorder`  | peer → directory  | Private coinjoin negotiation         |
| `!relorder`  | peer → directory  | Private coinjoin negotiation         |
| `!ioauth`    | peer → directory  | Private coinjoin auth                |
| `!txsigs`    | peer → directory  | Private coinjoin tx sigs             |
| `!pushtx`    | peer → directory  | Private transaction push             |
| `!disconnect`| peer → directory  | Graceful disconnect                  |
| `!getpeers`  | peer → directory  | Request maker list                   |
| `!peers`     | directory → peer  | Maker list response                  |
| `!ping`      | directory → peer  | Liveness check                       |
| `!pong`      | peer → directory  | Liveness response                    |
