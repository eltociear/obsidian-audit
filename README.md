# obsidian-audit

**Scan Obsidian community plugins for malicious patterns before you enable them.** Zero dependencies, one file, MIT.

```bash
python obsidian_audit.py --vault ~/Notes            # every plugin installed in a vault
python obsidian_audit.py --plugin dataview          # latest release, straight from the community directory
python obsidian_audit.py ~/Notes/.obsidian/plugins/some-plugin
# 🟢 dataview (blacksmithgu/obsidian-dataview)  [SAFE]  score=0  (0 findings, 3 info)
#     context  dynamic_code, network, vault_enum
```

## Why this exists

On desktop, an Obsidian community plugin is a `main.js` bundle running inside Electron with
**full Node.js access**. It can read any file your user account can read (not only your vault),
spawn processes, and talk to any host. Obsidian reviews a plugin when it is first submitted to
the directory, but **later releases are published straight from the author's GitHub repo and are
not re-reviewed**. One compromised maintainer account, or one bad update, and every user who
auto-updates runs the new code.

`obsidian-audit` statically reads the published `main.js` (it never executes it) and flags:

| Pattern | Severity |
| --- | --- |
| Remote code load: downloaded text passed to `eval` / `new Function` | CRITICAL |
| Download & execute: `curl … \| sh` / `iex (iwr …)` handed to `exec`/`spawn` | CRITICAL |
| Vault exfiltration: whole-vault read + a hard-coded collector (webhook, paste, tunnel, OAST) | CRITICAL |
| Credential exfiltration: `~/.ssh`, `~/.aws`, Keychain read + a collector | CRITICAL |
| `JSON.stringify(process.env)` with a network sink | CRITICAL |
| Reverse shell, home-directory wiper, crypto-miner pool | CRITICAL |
| Hard-coded collector endpoint (Discord/Slack webhook with token, `webhook.site`, ngrok/OAST subdomain) | HIGH |
| Browser credential store / wallet-extension storage access | HIGH |
| Obfuscated code (javascript-obfuscator output, packed `eval`, decode→eval) | HIGH |
| DNS exfiltration, global `NODE_TLS_REJECT_UNAUTHORIZED=0` | HIGH |
| Reading another app's secret from the macOS Keychain / Windows Credential Manager | MEDIUM |
| Client-side telemetry SDK endpoint (LOW if disclosed in the README/description) | MEDIUM |
| Public raw-IP URL next to a credential/env read | MEDIUM |

14 scored patterns (40 signatures) plus 4 file-level combination rules, and 12 informational
capability patterns. Deterministic: no LLM, no network needed to score.

Obfuscation and client-side telemetry are also against
[Obsidian's developer policies](https://docs.obsidian.md/Developer+policies), so a hit on either
is worth a look even when the plugin is benign.

## Calibrated, not noisy

A plugin bundle is not hand-written code: it is the plugin plus every library it pulled in
(CodeMirror, pdf.js, mermaid, KaTeX, LLM SDKs, wasm blobs). A naive rule set flags **39%** of
the 1,476 most-downloaded plugins, because popular plugins legitimately use `child_process`
(git, pandoc), read outside the vault, `eval` inside template engines, and ship megabytes of
base64 fonts and wasm. Those are **capabilities**, reported as `context` and never scored.
Risk comes from specific sinks and combinations.

Measured on the real directory (scan of 2026-11-25):

| Set | Plugins | CRITICAL | HIGH | MEDIUM |
| --- | --- | --- | --- | --- |
| Calibration: top 1,500 by downloads | 1,476 | 0 | 2 | 4 |
| Held-out: 1,000 random from the rest | 950 | 0 | 0 | 1 |

Both calibration HIGHs are real javascript-obfuscator output (identifier renaming and RC4
string arrays), which is what that rule is for. **No false positives at HIGH or CRITICAL.**

**Full results: [FINDINGS.md](FINDINGS.md)**: capability statistics for the directory, the noise
taxonomy, and what was (and was not) found.

## Usage

```bash
# local: a plugin folder, a main.js, or a whole vault
python obsidian_audit.py ~/Notes/.obsidian/plugins/some-plugin
python obsidian_audit.py --vault ~/Notes

# remote: the latest GitHub release, resolved through obsidianmd/obsidian-releases
python obsidian_audit.py --plugin dataview templater-obsidian
python obsidian_audit.py --repo owner/my-plugin

# the whole community directory, most-downloaded first
python obsidian_audit.py --all --limit 200 --json > scan.json

# a string
python obsidian_audit.py --text "eval(await (await fetch(u)).text())"
```

`--json` for machine-readable output, `--verbose` to print every INFO item. Exit code 2 if any
target is HIGH or CRITICAL, so it drops into CI or a pre-update hook:

```bash
python obsidian_audit.py --vault ~/Notes || echo "review before enabling"
```

Works on Python 3.8+ (tested on 3.9). Big bundles are fine: base64/hex blobs of
4 KB or more (wasm, fonts, images) are collapsed to placeholders before matching, and every
signature runs over bounded 8 KB windows, so the largest plugin in the directory (128 MB) scans
in about 7 s. A typical plugin takes under 0.1 s.

## Tests

```bash
python tests/run.py
```

14 inert malicious canaries (remote-code load, vault exfil to a Discord webhook and, in the
esbuild `(0, import_obsidian.requestUrl)(...)` form, to a tunnel, SSH-key
stealer, Keychain exfil, env dump, pipe-to-shell, reverse shell, wiper, miner, wallet/browser
theft, two obfuscator styles, undisclosed telemetry) and 7 benign controls modelled on real
popular plugins (git integration, self-hosted sync, plugin manager, shell commands, bundled
template engine, disclosed telemetry, Keychain read for the app's own API), plus a regression
test that a 5 MB single-line minified bundle scans in a few seconds. Canary hosts are reserved
(`.invalid`, TEST-NET) and canary tokens are obviously fake.

## Related

- [mcp-audit](https://github.com/eltociear/mcp-audit): the same engine for MCP servers and AI-agent skills
- [npm-audit](https://github.com/eltociear/npm-audit): malicious-pattern scan for npm packages
- [homebrew-audit](https://github.com/eltociear/homebrew-audit): formulae, casks and taps
- [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp): CLI, GitHub Action, Docker image and MCP server

*Findings are pattern matches warranting human review, not verdicts. Report a suspected
malicious plugin to the Obsidian team and the author, not as a public accusation.*

## License

MIT
