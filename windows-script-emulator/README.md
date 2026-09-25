# windows-script-emulator

`windows-script-emulator` is a bounded, hermetic JScript and VBScript
interpreter for Windows payload analysis. It models Windows Script Host, MSHTA,
scriptlets, common decoding functions, and high-value COM automation objects.
Native processes are never started, and all files and registry values remain
virtual. Network requests become typed `emulator-core` host activity and are
blocked by default; `--allow-network` explicitly enables bounded public
HTTP(S) retrieval.

```console
cargo run -p windows-script-emulator -- -c 'WScript.Echo(String.fromCharCode(79,75))'
cargo run -p windows-script-emulator -- --language vbscript -c 'WScript.Echo Chr(79) & Chr(75)'
cargo run -p windows-script-emulator -- --file samples/windows-script/download.hta --web-response benign
cargo run -p windows-script-emulator -- --allow-network --file samples/windows-script/download.hta
printf 'WScript.Echo("stdin")' | cargo run -p windows-script-emulator
```

Use `--host wscript|cscript|mshta|scriptlet`, repeatable `--arg` and
`--env NAME=VALUE`, `--trace`, `--web-response TEXT`, and `--allow-network` to
configure a run. Exact synthetic responses take precedence over real network
access.
With no input in a terminal, a history-enabled prompt keeps variables between
entries.

Library users create `WindowsScriptEmulator` and call `emulate` with a
`ScriptLanguage`, `ScriptHost`, argument slice, mutable `emulator_core::Host`,
and analysis depth. Variables persist within the emulator instance. The
interpreter is intentionally tolerant and analysis-oriented rather than a
browser or Windows Script Host compatibility layer.

When the supplied host implements synchronous `process_request`, modeled
`WScript.Shell.Exec` objects expose `Status`, `ExitCode`, `StdOut.ReadAll`,
`StdOut.ReadLine`, `StdErr`, and `AtEndOfStream`. `Run` honors its
`bWaitOnReturn` argument and returns the modeled child exit code. Hosts without
synchronous execution retain the process as a deferred typed intent.
