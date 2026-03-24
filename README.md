# flowra-relayer

**Flowra Relayer** — a fork of [jito-relayer](https://github.com/jito-foundation/jito-relayer) configured for the Flowra MEV stack.

## Changes from upstream

| Change | Detail |
|--------|--------|
| `--packet-delay-ms` default | Changed `50ms → 0ms` (Flowra target: zero delay) |
| Proto extensions | `block_engine.proto` extended with `ProgramsOfInterestRequest/Update` and `SubscribeProgramsOfInterest` RPC |
| `AccountsOfInterestUpdate` | Changed from `oneof msg` to flat `repeated string accounts` field to match jito-relayer's actual usage |

## What the relayer does

The relayer sits between the validator's TPU and the block engine:

```
Validators/Users ──QUIC──▶ flowra-relayer ──gRPC──▶ flowra-engine
                                │                         │
                         (ExpiringPacketStream)    (mempool broadcast)
                                                         ▼
                                                     Searchers
```

1. Receives transactions via QUIC TPU
2. Authenticates with flowra-engine (`Role::Relayer`)
3. Subscribes to Accounts of Interest + Programs of Interest from the engine
4. Filters and forwards matching transactions to the engine via `StartExpiringPacketStream`
5. Heartbeats maintain the bidirectional stream

## Build

```bash
source ~/.cargo/env
cargo build --release --bin jito-transaction-relayer
```

## Run

```bash
./target/release/jito-transaction-relayer \
  --keypair-path               /path/to/relayer-identity.json \
  --signing-key-pem-path       /path/to/relayer-signing.pem \
  --verifying-key-pem-path     /path/to/relayer-verifying.pem \
  --rpc-servers                http://127.0.0.1:8899 \
  --block-engine-url           http://127.0.0.1:11228 \
  --block-engine-auth-service-url http://127.0.0.1:8003 \
  --packet-delay-ms            0 \
  --grpc-bind-ip               0.0.0.0 \
  --grpc-bind-port             11230
```

### Key flags

| Flag | Default | Description |
|------|---------|-------------|
| `--block-engine-url` | — | flowra-engine relayer port (11228) |
| `--block-engine-auth-service-url` | same as above | flowra-engine auth port (8003) |
| `--packet-delay-ms` | `0` | Packet forwarding delay (upstream default was 50ms) |
| `--keypair-path` | — | Relayer identity keypair (used for auth challenge signing) |

### Generating keys

```bash
# Relayer identity keypair
solana-keygen new -o relayer-identity.json

# RSA signing keys for JWT (relayer's own auth service for validators)
openssl genrsa -out relayer-signing.pem 2048
openssl rsa -in relayer-signing.pem -pubout -out relayer-verifying.pem
```

## Connection flow

1. Relayer connects to `--block-engine-auth-service-url` and authenticates with `Role::Relayer`
2. Connects to `--block-engine-url` and calls `SubscribeAccountsOfInterest` + `SubscribeProgramsOfInterest`
3. Engine returns wildcard `["*"]` — relayer forwards all packets
4. Opens `StartExpiringPacketStream` bidirectional stream
5. All incoming QUIC packets are forwarded to the engine after filtering
6. Engine distributes packets to subscribed searchers via `SubscribePendingTransactions`

## Monitoring

Key metrics in logs:
- `block_engine_relayer-loop_stats`: `heartbeat_count`, `num_packets_received`, `packet_forward_count`
- `forwarder_metrics`: `num_be_packets_forwarded`, `num_be_packets_dropped`
- `relayer_metrics`: `num_current_connections`, `num_heartbeats`
