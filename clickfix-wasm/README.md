# clickfix-wasm

Browser wrapper for `clickfix-detect`.

```javascript
import init, {
  analyze_payload,
  analyze_payload_thorough,
  prefilter_payload,
} from './clickfix_wasm.js';

await init();
const prefilter = prefilter_payload(await navigator.clipboard.readText());
const { input_kind, report } = analyze_payload(
  'mshta.exe https://example.invalid/fix-error',
  'auto',
);
```

Accepted input kinds are `auto`, `command`, `powershell`, `bash`, and
`linux-bash`. The returned value is a JavaScript object containing the inferred
input kind and the complete serialized `AnalysisReport`.

`prefilter_payload` is intended for clipboard hot paths. Call
`analyze_payload` only when its decision is `candidate`; `definitely_benign`
inputs are not hashed, tokenized, or emulated.

`analyze_payload_thorough` bypasses the hot-path skip and always attempts
emulation. Reports identify their `analysis_mode` and whether analysis was
`prefilter_only`, `emulated`, or `partial`.

The current report schema is version 6. It includes `binary_inspections`,
typed `causal_edges`, and optional binary-inspection SHA-256 links on artifacts
and virtual files. Binary inspections now include signature-validation and ELF
GNU-property results. Function signatures and accepted input kinds are
unchanged.

The prefilter also returns `oversized` for inputs above the detector's 1 MiB
limit. Full reports include the same prefilter decision and signal list.

The browser build cannot enable the native HTTP transport. Payload emulation,
filesystem state, registry state, process dispatch, findings, URLs, IOCs,
artifacts, and trace output remain local to the WebAssembly instance.
