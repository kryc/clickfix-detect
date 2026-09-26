# clickfix-wasm

Browser wrapper for `clickfix-detect`.

```javascript
import init, { analyze_payload, prefilter_payload } from './clickfix_wasm.js';

await init();
const prefilter = prefilter_payload(await navigator.clipboard.readText());
const { input_kind, report } = analyze_payload(
  'mshta.exe https://example.invalid/fix-error',
  'auto',
);
```

Accepted input kinds are `auto`, `command`, and `powershell`. The returned
value is a JavaScript object containing the inferred input kind and the complete
serialized `AnalysisReport`.

`prefilter_payload` is intended for clipboard hot paths. Call
`analyze_payload` only when its decision is `candidate`; `definitely_benign`
inputs are not hashed, tokenized, or emulated.

The prefilter also returns `oversized` for inputs above the detector's 1 MiB
limit. Full reports include the same prefilter decision and signal list.

The browser build cannot enable the native HTTP transport. Payload emulation,
filesystem state, registry state, process dispatch, findings, URLs, IOCs,
artifacts, and trace output remain local to the WebAssembly instance.
