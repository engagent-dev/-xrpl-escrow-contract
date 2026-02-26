# XRPL Smart Escrow — WASM Analysis Guide

## Overview

This document covers the setup and analysis of the **multi-condition-escrow** WASM smart contract for the XRP Ledger, using Octopus (static analyzer), wasmtime, and supporting tools.

---

## Environment Setup

### 1. Install Miniconda (WSL/Linux)

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
source ~/.zshrc
```

### 2. Create the `wasm` Conda Environment

```bash
conda create -n wasm python=3.11
conda activate wasm
```

### 3. Install Python Packages

```bash
pip install octopus wasmtime
```

### 4. Patch Octopus for Python 3.11+

Octopus depends on the `wasm` package which uses `collections.Callable`, removed in Python 3.10+. Fix it:

```bash
sed -i 's/collections.Callable/collections.abc.Callable/g' \
  $(python -c "import wasm.types; print(wasm.types.__file__)")
```

Verify the fix:

```bash
python -c "from octopus.arch.wasm.analyzer import WasmModuleAnalyzer; print('Octopus OK')"
```

### 5. Install Rust WASM Target & Tools

```bash
rustup target add wasm32-unknown-unknown
brew install binaryen wabt
```

---

## Building the Contract

```bash
conda activate wasm
cargo build --target wasm32-unknown-unknown --release
```

The output binary is at:

```
target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm
```

### Optimize for Size

```bash
wasm-opt -Oz --enable-bulk-memory \
  target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm \
  -o target/wasm32-unknown-unknown/release/multi_condition_escrow_optimized.wasm
```

### Decompile to Readable Text (optional)

```bash
wasm2wat target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm
```

---

## Analysis with Octopus

### Run the Analyzer

```python
from octopus.arch.wasm.analyzer import WasmModuleAnalyzer

with open('target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm', 'rb') as f:
    wasm_bytes = f.read()

analyzer = WasmModuleAnalyzer(wasm_bytes)
analyzer.analyze()

# Print exports
for e in analyzer.exports:
    print(e)

# Print imports
for i in analyzer.imports_func:
    print(i)

# Print function prototypes
for f in analyzer.func_prototypes:
    print(f)
```

### Analysis Results

**Binary size:** 2,311 bytes

#### Exports (functions rippled can call)

| Name               | Kind     | Index | Description                    |
|--------------------|----------|-------|--------------------------------|
| `memory`           | Memory   | 0     | Shared memory for host access  |
| `finish`           | Function | 7     | Main escrow release logic      |
| `revoke_approval`  | Function | 10    | Lock escrow (set approved=0)   |
| `set_approval`     | Function | 11    | Unlock escrow (set approved=1) |
| `__data_end`       | Global   | 1     | End of static data segment     |
| `__heap_base`      | Global   | 2     | Start of heap memory           |

#### Imports (host functions the contract requires from rippled)

| Module     | Function                       | Signature              | Purpose                              |
|------------|--------------------------------|------------------------|--------------------------------------|
| `host_lib` | `get_tx_field`                 | `(i32, i32, i32) → i32` | Read fields from the current tx    |
| `host_lib` | `get_current_ledger_obj_field` | `(i32, i32, i32) → i32` | Read fields from the escrow object |
| `host_lib` | `update_data`                  | `(i32, i32) → i32`      | Write contract data to the escrow  |
| `host_lib` | `trace`                        | `(i32, i32, i32, i32, i32) → i32` | Debug logging             |
| `host_lib` | `trace_num`                    | `(i32, i32, i64) → i32` | Debug logging (numeric)            |

#### Function Prototypes

| Name               | Params         | Returns | Type   | Notes                          |
|--------------------|----------------|---------|--------|--------------------------------|
| `get_tx_field`     | `i32 i32 i32`  | `i32`   | import | Read transaction fields         |
| `update_data`      | `i32 i32`      | `i32`   | import | Write escrow contract data      |
| `trace`            | `i32 i32 i32 i32 i32` | `i32` | import | Debug trace                |
| `get_current_ledger_obj_field` | `i32 i32 i32` | `i32` | import | Read escrow object fields |
| `trace_num`        | `i32 i32 i64`  | `i32`   | import | Numeric debug trace             |
| `$func5`           | `i32`          | —       | local  | Internal helper (panic handler) |
| `$func6`           | `i32`          | `i32`   | local  | Internal helper (contains_key_value) |
| `finish`           | —              | `i32`   | export | Main escrow finish logic        |
| `$func8`           | `i32 i32 i32`  | —       | local  | Internal helper (memory ops)    |
| `$func9`           | `i32 i32`      | —       | local  | Internal helper (memory ops)    |
| `revoke_approval`  | —              | `i32`   | export | Revoke approval flag            |
| `set_approval`     | —              | `i32`   | export | Set approval flag               |
| `$func12`          | —              | —       | local  | Internal helper (allocator)     |

#### Memory

- **Initial:** 17 pages (1.1 MB)
- **Maximum:** None (unbounded)
- **Note:** Each WASM page = 64 KB

#### Other

- **Emscripten compiled:** No (pure Rust → WASM)
- **Globals:** 3 globals (stack pointer, data end, heap base)

---

## Quick Validation with wasmtime

```python
import wasmtime

with open('target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm', 'rb') as f:
    wasm_bytes = f.read()

engine = wasmtime.Engine()
module = wasmtime.Module(engine, wasm_bytes)

print(f"Binary size: {len(wasm_bytes)} bytes")

export_names = [e.name for e in module.exports]
for fn_name in ["finish", "set_approval", "revoke_approval"]:
    status = "FOUND" if fn_name in export_names else "MISSING"
    print(f"[{status}] {fn_name}")
```

---

## Contract Logic Summary

The contract enforces conditions before an escrow can release funds:

1. **Account verification** — reads the transaction sender via `get_tx_field`
2. **Time-lock** — checks `finish_after` on the escrow object via `get_current_ledger_obj_field`
3. **Approval flag** — reads contract data from the escrow and checks for `approved=1`

Return values:
- `1` (positive) → funds released
- `-1` → wrong account
- `-2` → too early
- `-3` → not approved
- `-4` → data read error
- `-5` → host call error

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `collections.Callable` error | Run the `sed` patch command above |
| `octopus-wasm` not found on pip | Install `octopus` (not `octopus-wasm`) |
| `WasmAnalyzer` import error | Use `WasmModuleAnalyzer` instead |
| Pass file path to analyzer | Read bytes first: `open(path, 'rb').read()` |
| `wasm-opt` validation errors | Add `--enable-bulk-memory` flag |
| `brew` not found in conda | Run `export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"` |