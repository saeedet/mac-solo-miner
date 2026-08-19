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
| M3 CPU, all 8 cores | ~200 MH/s (estimate) | ~87,000,000 years |
| Bitaxe Gamma | 1.2 TH/s | ~14,500 years |

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
| `btc-primitives` | Block headers, transactions, varints, merkle trees, difficulty targets. Pure, no I/O. |
| `bitcoind-rpc` | Typed JSON-RPC client for `getblocktemplate` / `submitblock`. |
| `stratum` | Stratum V1 wire types, shared by pool and miner so they cannot disagree. |
| `pool` | The solo mining pool (`solo-pool`). |
| `miner` | The hashing client (`mac-miner`). |

## Phases

- [x] **0** — Toolchains, repo skeleton, regtest node running
- [ ] **1** — `sha256d`: reproduces the genesis and block-100000 hashes
- [ ] **2** — `btc-primitives`: rebuilds a real block's merkle root from its txids
- [ ] **3** — Monolithic regtest miner — *bitcoind accepts a block we mined*
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
