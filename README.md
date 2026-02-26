# XRPL Multi-Condition Smart Escrow (Rust → WASM)

## What Is This?

A Rust smart contract for the XRP Ledger that compiles to WebAssembly.
Uses **`xrpl-wasm-stdlib`** (XRPL's equivalent of Solana's Anchor framework)
and the **`craft`** CLI tool.

The contract enforces 3 conditions before releasing escrowed XRP:
1. Caller must be the authorized notary account
2. Ledger sequence must be past a time-lock threshold
3. An on-chain approval flag must be set to "1"

## Quick Start — Copy & Paste These

```bash
# 1. Add WASM compile target (one-time)
rustup target add wasm32-unknown-unknown

# 2. Run the 10 unit tests
cargo test

# 3. Run tests with full output
cargo test -- --nocapture

# 4. Build the WASM binary
cargo build --target wasm32-unknown-unknown --release

# 5. See the compiled .wasm file
ls -lh target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm

# ══════════════════════════════════════════════════════════
# Optional: On-chain testing with craft CLI
# ══════════════════════════════════════════════════════════

# Install craft (XRPL's "anchor" equivalent)
cargo install craft

# Test in simulated XRPL host environment
craft test multi-condition-escrow --all --verbose

# Deploy to local rippled (needs Docker)
craft start-rippled
craft deploy multi-condition-escrow
craft advance-ledger --count 10
craft open-explorer
craft stop-rippled

# Deploy to public Devnet
craft deploy multi-condition-escrow --network devnet
```

## How XRPL Smart Escrows Work

```
Alice (Sender)                    Escrow (On-Ledger)
    │                                  │
    │── EscrowCreate ────────────────> │  Amount: 100 XRP
    │   + WASM bytecode                │  WASM:   [our Rust code]
    │   + initial data                 │  Data:   {approved: "0"}
    │                                  │
    │                                  │
Bob (Notary)                           │
    │                                  │
    │── EscrowFinish ────────────────> │  WASM VM runs finish()
    │                                  │  return > 0? → release funds
    │                                  │  return ≤ 0? → deny
```

## Solana Anchor vs XRPL Comparison

| Concept | Solana (Anchor) | XRPL (xrpl-wasm-stdlib) |
|---|---|---|
| Language | Rust | Rust |
| Compile target | BPF | WASM |
| Framework | `anchor-lang` | `xrpl-wasm-stdlib` |
| CLI | `anchor` | `craft` |
| Entry point | `#[program]` | `pub extern "C" fn finish()` |
| State | Account data | Escrow Data field |
| Deploy | `anchor deploy` | `craft deploy` |
| Test | `anchor test` | `craft test` / `cargo test` |

```bash
xrpl-smart-contract/
├── Cargo.toml                          # 1
├── setup.sh                            # 2
├── src/
│   └── lib.rs                          # 3
└── fixtures/
    ├── success/
    │   ├── escrow.json                 # 4
    │   └── transaction.json            # 5
    └── failure/
        ├── escrow.json                 # 6
        └── transaction.json            # 7
```


1. Cargo.toml — The package manifest. Tells Rust the project name, what dependencies to pull (xrpl-wasm-stdlib), and that this should compile as a cdylib (C dynamic library) so it produces a .wasm file instead of a normal binary. Also has the release profile settings that shrink the WASM to the smallest possible size for on-chain deployment.

2. setup.sh — One-shot script that installs Rust if missing, adds the WASM compile target, runs tests, and builds the binary. It's a convenience wrapper so you can just ./setup.sh and everything happens.

3. src/lib.rs — The actual smart contract. This is the only file that gets compiled and deployed on-chain. It contains the finish() function that the XRPL node calls when someone tries to release an escrow. It checks 3 conditions (right account, enough time passed, approval flag set), and returns a positive number to release funds or negative to deny. Also has set_approval() and revoke_approval() bonus functions. The bottom half is the 10 unit tests that mock the host environment so you can test the logic with cargo test without needing an actual XRPL node.

4. 5. fixtures/success/ — Fake XRPL data for the passing test case. escrow.json is what the escrow object looks like on-chain (with approved: "1"). transaction.json is the EscrowFinish transaction from the correct notary account at a valid ledger sequence. When craft test runs, it feeds these to the WASM sandbox and expects finish() to return > 0.

6. 7. fixtures/failure/ — Fake XRPL data for the failing test case. The transaction.json has a different account (unauthorized), and escrow.json has approved: "0". The WASM should return a negative number, meaning "don't release the funds."
The key thing: only src/lib.rs goes on-chain. Everything else is tooling and test data that stays on your machine.



# XRPL Multi-Condition Smart Escrow — What It Does

## The One-Liner

A Rust smart contract that locks XRP in an escrow and only releases it when **three conditions are all true at the same time**.

---

## The Scenario

Alice wants to pay Bob 100 XRP, but only if:

- A specific **trusted notary** (think lawyer, compliance officer, or automated oracle) signs off on it
- Enough **time has passed** (measured in ledger closes, not wall-clock time)
- Someone has explicitly **flipped an approval switch** stored on-chain

If any one of those conditions is missing, the money stays locked. Nobody can touch it.

---

## The Three Conditions

### Condition 1 — Account Verification

The contract hardcodes an authorized notary address (`rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh`). When someone submits a transaction to release the escrow, the contract asks the XRPL node: "who signed this transaction?" If the answer isn't the notary, it immediately returns `-1` and the funds stay locked.

This prevents random people from draining the escrow.

### Condition 2 — Time-Lock (Ledger Sequence)

The contract requires the current ledger sequence to be at least `1000`. Each XRPL ledger closes roughly every 3–5 seconds, so this acts as a time delay of about 50–80 minutes after the escrow was created.

The XRPL doesn't give contracts access to wall-clock time because that would break deterministic execution across validators — every validator needs to get the same result. Ledger sequence is the universal clock that all nodes agree on.

### Condition 3 — Approval Flag

The escrow has a small on-chain key-value store called the "Data field." The contract reads the key `"approved"` and checks if the value is exactly `"1"`. If it's `"0"`, missing, or anything else, the release is denied.

This flag could be set by an off-chain oracle (e.g., "the shipment arrived"), a compliance system (e.g., "KYC passed"), or the notary themselves. It separates the **decision** to approve from the **action** of releasing funds.

---

## How It Runs On-Chain

```
1. Alice creates an escrow on the XRPL:
   - Locks 100 XRP
   - Attaches the compiled WASM bytecode (this Rust contract)
   - Sets initial data: { approved: "0" }
   - Sets a cancel-after date (safety net)

2. Time passes. The oracle/notary updates the approval flag to "1".

3. The notary submits an EscrowFinish transaction.

4. The XRPL node loads the WASM code from the escrow,
   spins up a sandboxed WebAssembly VM, and calls finish().

5. finish() checks all 3 conditions:
   ✓ Account matches the notary
   ✓ Ledger sequence >= 1000
   ✓ Data["approved"] == "1"

6. finish() returns 1 (positive) → XRPL releases 100 XRP to Bob.

   If ANY check fails, finish() returns a negative number
   and the transaction is rejected. Funds stay locked.
```

---

## The Bonus Functions

The contract also exports `set_approval()` and `revoke_approval()`. These are for the upcoming XLS-101 Smart Contracts system (currently on AlphaNet) where contracts can have multiple callable functions, not just `finish()`. They let the notary flip the approval flag on or off, with the same account verification so only the notary can do it.

---

## What It Doesn't Do

- It doesn't move funds itself — the XRPL handles that based on the return value
- It can't access the internet, filesystem, or anything outside the sandbox
- It can't run forever — the XRPL enforces gas limits and will kill it if it takes too long
- It can't modify anything except the escrow's own Data field

---

## Real-World Use Cases for This Pattern

| Use Case | Condition 1 | Condition 2 | Condition 3 |
|---|---|---|---|
| **Real estate closing** | Escrow agent's account | 30-day inspection period | Title search approved |
| **Freelancer payment** | Client's account | 7-day review period | Deliverable accepted |
| **Supply chain** | Shipping company | Delivery window elapsed | GPS confirms arrival |
| **Compliance hold** | Compliance officer | Regulatory waiting period | KYC/AML check passed |
| **Bet / prediction** | Oracle service | Event date passed | Oracle confirms outcome |