#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# setup.sh — One-shot setup, build, and test for the XRPL
#             Multi-Condition Smart Escrow contract
#
# USAGE (from your Downloads folder):
#   cd /mnt/c/Users/devon/Downloads/xrpl-smart-contract
#   chmod +x setup.sh
#   ./setup.sh
# ═══════════════════════════════════════════════════════════════
set -e

echo "════════════════════════════════════════════════════════"
echo "  XRPL Smart Contract — Setup & Test"
echo "════════════════════════════════════════════════════════"
echo ""

# ───────────────────────────────────────────────────────────────
# STEP 1: Check if Rust is installed
# ───────────────────────────────────────────────────────────────
if ! command -v rustc &> /dev/null; then
    echo "⚠  Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✓ Rust installed"
else
    echo "✓ Rust found: $(rustc --version)"
fi

# ───────────────────────────────────────────────────────────────
# STEP 2: Add WASM target
# ───────────────────────────────────────────────────────────────
echo ""
echo "► Adding wasm32-unknown-unknown target..."
rustup target add wasm32-unknown-unknown 2>/dev/null || true
echo "✓ WASM target ready"

# ───────────────────────────────────────────────────────────────
# STEP 3: Run native Rust tests (no WASM host needed)
# ───────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Running Unit Tests"
echo "════════════════════════════════════════════════════════"
echo ""
cargo test -- --nocapture
echo ""
echo "✓ All tests passed!"

# ───────────────────────────────────────────────────────────────
# STEP 4: Build the WASM binary
# ───────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Building WASM Binary"
echo "════════════════════════════════════════════════════════"
echo ""
cargo build --target wasm32-unknown-unknown --release
WASM_FILE="target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm"
echo ""
echo "✓ WASM binary built: $WASM_FILE"
echo "  Size: $(ls -lh $WASM_FILE | awk '{print $5}')"

# ───────────────────────────────────────────────────────────────
# STEP 5: Optimize (if wasm-opt is available)
# ───────────────────────────────────────────────────────────────
if command -v wasm-opt &> /dev/null; then
    echo ""
    echo "► Optimizing WASM binary..."
    wasm-opt -Oz $WASM_FILE -o target/optimized.wasm
    echo "✓ Optimized: target/optimized.wasm ($(ls -lh target/optimized.wasm | awk '{print $5}'))"
else
    echo ""
    echo "ℹ  wasm-opt not found (optional). Install binaryen for smaller binaries."
    echo "   Ubuntu: sudo apt install binaryen"
    echo "   macOS:  brew install binaryen"
fi

# ───────────────────────────────────────────────────────────────
# STEP 6: Check if craft CLI is available
# ───────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Next Steps"
echo "════════════════════════════════════════════════════════"
echo ""
if command -v craft &> /dev/null; then
    echo "✓ craft CLI found. You can run:"
    echo "  craft test multi-condition-escrow --all --verbose"
    echo "  craft start-rippled"
    echo "  craft deploy multi-condition-escrow"
else
    echo "ℹ  To deploy on-chain, install the craft CLI:"
    echo "   cargo install craft"
    echo ""
    echo "  Then run:"
    echo "   craft test multi-condition-escrow --all --verbose"
    echo "   craft start-rippled       # needs Docker"
    echo "   craft deploy multi-condition-escrow"
fi
echo ""
echo "  Or test interactively at:"
echo "  https://ripple.github.io/xrpl-wasm-stdlib/ui/"
echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✓ Done!"
echo "════════════════════════════════════════════════════════"
