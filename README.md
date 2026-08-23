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
| M3 CPU, all 8 cores | **96.6 MH/s** (measured) | ~180,000,000 years |
| Bitaxe Gamma | 1.2 TH/s | ~14,500 years |

The M3 figure is measured, not projected — run
`cargo run --release --example hashrate -p sha256d` to reproduce it. Getting
there took three steps from a 6.0 MH/s Phase 1 baseline:

| | Single core | |
|---|---|---|
| Portable reference | 1.4 MH/s | mirrors FIPS 180-4, not trying to be fast |
| ARMv8 crypto extensions | 6.0 MH/s | hardware SHA-256 instructions |
| \+ midstate, no allocation | 17.9 MH/s | the header's first 64 bytes never change |

and then near-linear scaling: 34.1 MH/s on 2 threads, 68.5 on 4, 96.6 on 8. The
step from 4 to 8 adds less than the first four because the M3's second four
cores are efficiency cores.

An earlier guess of 200 MH/s was optimistic; a later projection of 70 MH/s was
pessimistic. Both have been replaced by measurement.

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
| `stratum` | Stratum V1 wire types, shared by pool and miner so they cannot disagree. Owns the byte-order conventions. |
| `solo-pool` | The solo mining pool: bitcoind on one side, Stratum on the other. |
| `mac-miner` | The hashing client. Knows nothing about blocks or the node. |

## Phases

- [x] **0** — Toolchains, repo skeleton, regtest node running
- [x] **1** — `sha256d`: reproduces the genesis and block-100000 hashes
- [x] **2** — `btc-primitives`: rebuilds a real block's merkle root from its txids
- [x] **3** — Monolithic regtest miner — *bitcoind accepts a block we mined*
- [x] **4** — Split into `solo-pool` + `mac-miner` over Stratum V1
- [x] **5** — Optimise: midstate, ARM crypto extensions, multithreading
- [x] **6** — testnet4 — *built a valid block a real node accepted as its tip*
- [x] **7** — Mainnet pruned node, "lottery mode"

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

### Run the pool and a miner

Two processes, real TCP between them:

```bash
cargo run --release -p solo-pool -- --network regtest
```

```bash
cargo run --release -p mac-miner -- --pool 127.0.0.1:3333 --worker mac.0
```

The miner uses one thread per logical core by default; `--threads N` overrides
it.

The pool serves Stratum V1, so `mac-miner` is replaceable: point an ASIC at
port 3333 instead and nothing on the pool side changes. That is the whole reason
the split exists.

### Mine on mainnet

```bash
./scripts/mine.sh mainnet --threads half
```

One command: it refuses to start unless the node is synced, validates the
payout address against the network, starts the pool and the miner, and stops
both on Ctrl-C. The payout address is read from
`~/.solo-mac-miner/payout.mainnet` — outside the repo, so it never reaches git.

`--threads half` uses four of eight cores for about 70% of full hashrate and
much less heat. The default leaves two cores free; `--threads max` uses all of
them.

Stopping costs nothing. Mining is memoryless, so an hour today and an hour next
month are worth exactly what two hours now would be — which is why
`~/.solo-mac-miner/lifetime.json` accumulates across sessions:

```
  30.83 MH/s (avg  30.50)   session  610.27M   best 30/78 bits   00000002894d5...
          lifetime  215.90G   best ever 38/78 bits (2^40 short)   ~1 in 2.503e12 of a block
```

`38/78` is the best hash ever found against the leading zero bits a block
actually needs. Read that as a fraction and it looks like halfway; it is not.
Bits are exponential, which is what the `2^40 short` is there to say — the best
hash in 215 billion attempts is still about a trillion times too easy.

The best-ever figure is worth nothing in consensus terms: a near miss is a miss,
and it says nothing about the next hash. It is tracked because it is the only
feedback solo mining ever gives.

### Measure the hasher

```bash
cargo run --release --example hashrate -p sha256d
```
