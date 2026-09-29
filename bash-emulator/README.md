# bash-emulator

Hermetic, bounded Bash-compatible shell emulation for macOS and Linux ClickFix
payload analysis.

The emulator tokenizes source into a span-preserving document, parses typed
pipelines and compound commands, expands shell variables without invoking the
host shell, and routes external commands through `emulator-core::ProcessIntent`.
Files and directories use a deterministic virtual macOS or Linux host; no
native command is executed.

Supported language surfaces include:

- single and double quotes, escapes, variables, parameter defaults, positional
  parameters, command substitution, backticks, arithmetic substitution, and
  tilde expansion;
- command lists, `&&`, `||`, pipelines, groups, subshells, functions, `if`,
  `for`, `while`, and `until`;
- assignments, exported variables, shell functions, positional arguments,
  return/exit/break/continue flow, and bounded loops;
- stdin/stdout/stderr pipelines and file redirection;
- common builtins and virtual filesystem operations.

```console
cargo run -p bash-emulator -- -c 'name=world; echo "hello $name"'
cargo run -p bash-emulator -- --platform linux -c 'pwd; echo "$HOME"'
cargo run -p bash-emulator -- --file sample.sh --arg one --arg two
cat sample.sh | cargo run -p bash-emulator
```

Use `--platform macos|linux`, `--trace` to print typed effects, and
`--env NAME=VALUE` to override the deterministic environment.

For transient compatibility corpora, run the parser-only checker:

```console
cargo run -p bash-emulator --example corpus_check -- path/to/corpus
```

It recursively tokenizes and constructs ASTs for shell scripts, aggregates
diagnostics, isolates parser panics per file, and never executes corpus input.
