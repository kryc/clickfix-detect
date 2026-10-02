# binary-inspector

Bounded structural inspection for untrusted PE, ELF, thin Mach-O, and universal
Mach-O bytes. The crate uses Goblin's strict parsers and never maps, loads, or
executes the inspected file.

`inspect` returns a neutral report containing:

- SHA-256, original size, inspected byte count, format, kind, architectures,
  endianness, bitness, and entry point;
- bounded sections or segments with file/virtual ranges and permissions;
- bounded imports, exports, dependencies, capability tags, and static
  indicators;
- basic ASLR/PIE, NX-stack, stack-canary, RELRO, CFG, high-entropy VA, and
  signature metadata where the format exposes it;
- section entropy, high-entropy section names, file overlays, common packer
  markers, PE certificate counts, Mach-O signature sizes and entitlement keys,
  and ELF build IDs, interpreters, and runtime paths;
- explicit partial status, truncation, and parser warnings for malformed or
  resource-bounded input.

```rust
use binary_inspector::{inspect, BinaryInspectionLimits};

let report = inspect(bytes, &BinaryInspectionLimits::default());
```

Limits are independent from virtual-file and artifact retention limits so a
caller can inspect original downloaded bytes before retaining a smaller virtual
copy. Fuzz targets for all three format families live under `fuzz/`.
