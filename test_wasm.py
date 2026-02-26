import wasmtime

wasm_file = "target/wasm32-unknown-unknown/release/multi_condition_escrow.wasm"

print("=== Analyzing WASM binary ===\n")

with open(wasm_file, "rb") as f:
    wasm_bytes = f.read()

print(f"Binary size: {len(wasm_bytes)} bytes")

engine = wasmtime.Engine()
module = wasmtime.Module(engine, wasm_bytes)

print(f"\nExports:")
for exp in module.exports:
    print(f"  - {exp.name} ({exp.type})")

print(f"\nImports:")
for imp in module.imports:
    print(f"  - {imp.module}.{imp.name} ({imp.type})")

export_names = [e.name for e in module.exports]
print()
for fn_name in ["finish", "set_approval", "revoke_approval"]:
    status = "FOUND" if fn_name in export_names else "MISSING"
    print(f"[{status}] {fn_name}")