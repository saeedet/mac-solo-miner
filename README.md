# solo-mac-miner

A solo Bitcoin miner built from scratch in Rust, running against a local pruned
Bitcoin Core node on an Apple Silicon Mac.

The goal is understanding, not revenue. Every piece that could be pulled off the
shelf — the hash function, the block assembly, the pool protocol, the mining
loop — is written here instead, so the whole path from "a block template" to
"a valid block" is visible and legible.

## The honest odds

At a network difficulty of ~127.5T, expected time to find a block is
`difficulty × 2³² / hashrate`:

| Hardware | Hashrate | Expected time to a block |
|---|---|---|
| M3 CPU, all 8 cores | ~70 MH/s (projected) | ~250,000,000 years |
| Bitaxe Gamma | 1.2 TH/s | ~14,500 years |

The M3 figure is a projection from a *measured* Phase 1 baseline of 6.0 MH/s on
one core (`cargo run --release --example hashrate -p sha256d`), assuming Phase 5
lands midstate caching and multithreading across 4 performance + 4 efficiency
cores. An earlier guess of 200 MH/s was optimistic and has been corrected.

This is a lottery ticket. It is not an income stream. Mining is *memoryless*:
every hash is an independent trial, so stopping and restarting costs nothing,
and running it for two hours now and then is a perfectly coherent way to use it.

## Architecture

```
bitcoind (pruned)  ──JSON-RPC──▶  solo-pool  ──Stratum V1──▶  mac-miner
   regtest             ZMQ          builds the block           finds the nonce
   testnet4                         template, validates
   mainnet                          shares, submits blocks
```

The pool and the miner are separate processes talking over real TCP. That is
not ceremony: it is what makes the protocol boundary honest, and it means an
ASIC (a Bitaxe, say) can later replace `mac-miner` as the hashing client
without the pool changing at all.

## Crate map

| Crate | Responsibility |
|---|---|
| `sha256d` | SHA-256 and double-SHA-256. Readable reference impl + ARM crypto-extension impl, tested against each other. |
| `btc-primitives` | Block headers, transactions, varints, merkle trees, difficulty targets. Pure, no I/O. Byte order is enforced by the type system. |
| `bitcoind-rpc` | Typed JSON-RPC client for `getblocktemplate` / `submitblock`. Cookie auth; hand-rolled HTTP and base64. |
| `mining` | Coinbase construction, block assembly, nonce search. Pure, no I/O. |
| `regtest-miner` | End-to-end miner for a local regtest chain. |
| `stratum` | Stratum V1 wire types, shared by pool and miner so they cannot disagree. |
| `pool` | The solo mining pool (`solo-pool`). |
| `miner` | The hashing client (`mac-miner`). |

## Phases

- [x] **0** — Toolchains, repo skeleton, regtest node running
- [x] **1** — `sha256d`: reproduces the genesis and block-100000 hashes
- [x] **2** — `btc-primitives`: rebuilds a real block's merkle root from its txids
- [x] **3** — Monolithic regtest miner — *bitcoind accepts a block we mined*
- [ ] **4** — Split into `solo-pool` + `mac-miner` over Stratum V1
- [ ] **5** — Optimise: midstate, ARM crypto extensions, multithreading
- [ ] **6** — testnet4 — *find a real block on a public network*
- [ ] **7** — Mainnet pruned node, "lottery mode"

## Quickstart

```bash
./scripts/node.sh start regtest
./scripts/node.sh cli regtest getblockchaininfo
./scripts/node.sh stop regtest
```

Chain data lives in `~/.bitcoin-solo`, deliberately outside both this repo and
Bitcoin Core's default datadir.

### Mine some blocks

With the regtest node running:

```bash
cargo run --release -p regtest-miner -- 10
```

Regtest difficulty is trivial — the target covers roughly half the hash space,
so a block takes a handful of attempts and 111 blocks take under a second. Every
consensus rule that applies on mainnet applies here too, so a block regtest
accepts is wrong in no way it is being lenient about.

### Measure the hasher

```bash
cargo run --release --example hashrate -p sha256d
```
