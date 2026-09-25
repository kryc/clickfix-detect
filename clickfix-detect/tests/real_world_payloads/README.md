# Published ClickFix payload corpus

These fixtures contain Base64-encoded command text published by
threat-research vendors. Tests decode each fixture in memory and pass it to
`clickfix-detect` without trimming, quote normalization, or adaptation to
emulator capabilities. Per-fixture SHA-256 values in
`../real_world_payloads.rs` cover the decoded bytes and make accidental changes
visible.

Publication-only safety notation such as `hxxp`, `hxxps`, `[:]`, and `[.]` is
refanged where the original host is known. This restores the command's observed
network semantics without changing its execution structure. Publisher
placeholders, truncation, malformed quoting, path traversal, unusual
capitalization, and generalized hosts remain untouched. Every Base64 fixture
has an adjacent heavily defanged comment in the test table for review.

The files are inert test data. Corpus tests use the default disabled network
policy: no native process, network connection, registry modification, or host
filesystem write occurs.

## Sources

| Publisher | Source | Fixtures |
| --- | --- | --- |
| Proofpoint | [From Clipboard to Compromise: A PowerShell Self-Pwn](https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn) | Three TA571 PowerShell clipboard commands |
| Unit 42 | [2024-08-28 Lumma Stealer IOC report](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2024-08-28-IOCs-for-Lumman-Stealer-from-fake-human-captcha-copy-paste-script.txt) | Three `mshta` commands |
| Unit 42 | [2026-08-05 pcalua/WebDAV variant](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-08-05-New-Clickfix-Variant.txt) | Templated `pcalua` chain and generalized `davclnt` command |
| Sekoia | [ClickFix Tactic: The Phantom Meet](https://www.sekoia.com/blog/clickfix-tactic-the-phantom-meet) | Fake Google Meet `mshta` command |
| Huntress | [ClickFix Gets Creative: Malware Buried in Images](https://www.huntress.com/blog/clickfix-malware-buried-in-images) | Hex-octet `mshta` command |
| Huntress | [ClickFix Removes Your Background but Leaves the Malware](https://www.huntress.com/blog/clickfix-castleloader-backgroundfix) | `%COMSPEC%`, caret-obfuscated `finger` chain |
| Huntress | [ClickFix, Matanbuchus 3.0, and AstarionRAT](https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis) | Mixed-case remote `msiexec` command |
| Fortinet | [From ClickFix to Command: A Full PowerShell Attack Chain](https://www.fortinet.com/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain) | Initial IEX command and two published follow-on PowerShell lines |
| CyberProof | [Beyond PowerShell: Analyzing the Multi-Action ClickFix Variant](https://www.cyberproof.com/blog/beyond-powershell-analyzing-the-multi-action-clickfix-variant/) | Multiline `cmdkey` and remote `regsvr32` chain |
| eSentire | [Unpacking NetSupport RAT Loaders Delivered via ClickFix](https://www.esentire.com/blog/unpacking-netsupport-rat-loaders-delivered-via-clickfix) | Two PowerShell cradles, two remote MSI commands, one truncated encoded command |
| Rapid7 | [ClickFix Phishing Campaign Masquerading as a Claude Installer](https://www.rapid7.com/blog/post/ve-clickfix-phishing-campaign-fake-claude-installer/) | Published cmd wrapper with encoded-command placeholder |
| Zscaler | [COLDRIVER Updates Its Arsenal](https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix) | Remote UNC `rundll32` command |
| Zscaler | [Technical Analysis of MLTBackdoor](https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor) | Templated headless `conhost` chain |
| The DFIR Report | [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) | PowerShell/WebClient Interlock loader command |

`Truncated` fixture metadata means the publication itself used a placeholder,
generalized host, omitted argument, or shortened encoded value. Tests do not
attempt to reconstruct missing content.

## Coverage gaps exposed by the corpus

1. **Generalized indicators:** publisher placeholders such as
   `hxxps://[.]com/` and `<PAYLOAD_HOST>` cannot be refanged without inventing
   evidence. Add a canonical indicator type that retains both published and
   executable forms when both are known. Canonical forms must never trigger
   real network access.
2. **Windows proxy executables:** `pcalua.exe` and
   `davclnt.dll,DavSetCookie` are detected but not recursively modeled.
   Headless `conhost.exe` command proxying is modeled.
3. **UNC and WebDAV resources:** remote `rundll32` and `regsvr32` paths are
   statically noted but cannot retrieve fixture-backed SMB/WebDAV content.
   Extend network fixtures with `smb://` and `webdav://` schemes and keep the
   returned bytes virtual.
4. **PowerShell web object shapes:** the eSentire
   `New-Object Net.WebClient`/`DownloadFile` form still records unsupported
   operations. Unify PowerShell WebClient instance state with the existing
   HTTP object model.
5. **PowerShell chained member evaluation:** nested expressions such as
   `IEX ((Invoke-RestMethod ...).note.body)` are detected, but the full
   property chain is not evaluated. Extend member access over response maps
   before invocation.
6. **Publication typography:** smart quotes, en-dash parameters, placeholders,
   and CMS-damaged quoting are intentionally retained. Add a secondary,
   provenance-marked tolerant parse candidate rather than mutating the primary
   input.
7. **Incomplete public evidence:** some reports publish commands only as
   screenshots; others replace encoded bodies or hosts with placeholders.
   Those cannot support byte-exact fixtures until a textual primary source is
   available.

The corpus also exposed and now covers several fixed gaps: blocked or invalid
archive content no longer aborts analysis; Windows Run environment variables
are expanded; `finger.exe` emits a typed network intent; `START` can proxy cmd
internal commands; unquoted `FOR /F` options are tolerated after nested parsing;
and nested child syntax errors are reported without discarding the parent
analysis.

Detector expectations distinguish provenance from standalone behavior. Complete
remote-launch and download/execute commands must be `Malicious`; incomplete
encoded placeholders remain `Suspicious`; and two isolated Fortinet retrieval
lines remain `Benign` because, without their surrounding script, they only
retrieve data and do not execute it. The separate benign corpus guards this
boundary against broad keyword or network-only scoring.
