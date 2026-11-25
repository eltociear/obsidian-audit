# What we found scanning 2,426 Obsidian community plugins

This is the research behind `obsidian-audit`: a scan of the published `main.js` of 2,426
community plugins, run with this exact engine and calibrated so that "clean" means clean before
any number is reported. Same method as [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md)
and [npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md).

## Why plugins are worth scanning

On desktop, a community plugin runs inside Electron with full Node.js access: it can read
anything your user account can read, spawn processes, and reach any host. The Obsidian team
reviews a plugin when it first joins the directory; after that, new versions ship straight
from the author's GitHub releases, and the Obsidian app's update button installs whatever the
latest release contains. The review protects the first version, not the hundredth.

## Method

1. Took the directory (`obsidianmd/obsidian-releases/community-plugins.json`, **10,844
   plugins** on 2026-11-24) and joined it with download counts.
2. **Calibration set:** the top 1,500 by downloads. **Held-out set:** 1,000 drawn at random
   (fixed seed) from the remaining 9,344, scanned only with the final engine.
3. For each plugin, downloaded `main.js` and `manifest.json` from the latest GitHub release,
   exactly what the Obsidian app installs. Nothing was executed.
4. 74 of the 2,500 had no `main.js` asset in their latest release (deleted, renamed, or a
   release without the build), leaving **2,426 scanned: 2.6 GB of JavaScript.**

## Headline

| Result | Calibration (1,476) | Held-out (950) |
| --- | --- | --- |
| **SAFE** | 1,470 | **949** |
| CRITICAL | 0 | **0** |
| HIGH | 2 (both real obfuscation) | **0** |
| MEDIUM | 4 | 1 |
| Naive rule set, HIGH or worse | 580 (39.3%) | 235 (24.7%) |

**No plugin in either set showed remote code loading, credential or vault exfiltration,
collector endpoints, wallet or browser-data access, reverse shells, wipers, miners, or DNS
beacons.** That is the expected result for the most-installed corner of a reviewed directory,
and it is what makes a CRITICAL from this scanner mean something.

## The noise: what looks dangerous in a plugin but isn't

A plugin's `main.js` is a bundle: the plugin plus every library it pulled in. A naive rule set
(any `eval`/`new Function`, `child_process`, credential-path string, pipe-to-shell string,
TLS-off flag, long encoded blob, or path outside the vault) flags a third of the directory.
Measured over all 2,426:

| Capability | Plugins | Why it's noise |
| --- | --- | --- |
| Network access | 996 (41.1%) | Sync, AI, publishing and import plugins. The risk is a *collector* destination, not a request |
| Whole-vault read (`getMarkdownFiles()` etc.) | 958 (39.5%) | Search, graph, tasks, dataview-style indexing |
| Whole-vault read **and** network | 526 (21.7%) | Sync and AI plugins. Sending notes to the service you configured is the product |
| Embedded base64/hex blobs ≥ 4 KB | 524 (21.6%) | wasm (sql.js, tree-sitter, pdfium), fonts, images. 206 bundles are over 3 MB, the largest 128 MB |
| Raw `fs` module | 334 (13.8%) | Attachments, exports, backups |
| `eval` / `new Function` on a non-literal | 230 (9.5%) | Template engines, sandboxes for user-written scripts, bundled libraries |
| `child_process` | 206 (8.5%) | git, pandoc, LaTeX, shell-command and terminal plugins |
| `child_process` **and** network | 134 (5.5%) | Git sync, CLI-backed AI agents |
| Paths built from the home dir / app-data dirs | 129 (5.3%) | Reading config of a companion CLI, export targets |
| `~/.ssh`, `~/.aws`, `.npmrc` references | 7 (0.3%) | Git plugins locating SSH keys for the user's own remote |
| `rejectUnauthorized: false` | 3 (0.1%) | Self-hosted servers with self-signed certificates |
| Writes into `.obsidian/plugins/` | 3 (0.1%) | Plugin managers and beta-installers |

Every one of these is a **capability**. `obsidian-audit` reports them as context and scores
only sinks and combinations: downloaded text into `eval`, a credential read *and* a hard-coded
collector, a vault read *and* a webhook with its token baked in.

Three calibration lessons that shaped the engine:

- **Install hints are not installs.** 6 plugins contain `curl … | bash` as text: install
  instructions they show the user ("install the CLI first") or a bundled CI snippet. The scanner only treats pipe-to-shell as CRITICAL when the
  same statement hands it to `exec`/`spawn`; otherwise it is MEDIUM (if the plugin can spawn
  processes) or INFO.
- **A collector must be hard-coded to count.** Popular plugins contain the bare string
  `"ngrok.io"` (dev-server allow-lists) and call `api.telegram.org/bot${token}` with the
  *user's* token. Only webhooks with an id and token baked in, bot URLs with a literal token,
  and tunnel/OAST *subdomains* count.
- **Bundlers rename the API.** esbuild compiles `requestUrl(...)` to
  `(0, import_obsidian.requestUrl)(...)`. Missing that form undercounted network use by a
  third (26.8% → 41.1% once fixed) and would have let a vault-exfil combination slip through.
  There is now a canary for it.

## What was worth flagging

Stated as observed patterns, not verdicts. No plugin here is accused of anything.

**Obfuscated code: 2 plugins, both in the top 1,500.** Both ship `main.js` through
javascript-obfuscator: renamed `_0x…` identifiers, hex numerals, RC4-keyed string arrays. One
has 2,328 `_0x` identifiers; the other has 144 plus RC4-keyed string-array decoder calls
(`Pt(1082,"8F&P")` style) for nearly every property access. Obfuscation is not
evidence of malice (it is usually licence protection), but it is against
[Obsidian's developer policies](https://docs.obsidian.md/Developer+policies), and it makes the
code unreviewable. A user cannot tell what an obfuscated plugin with full Node access does with
their vault.

**Reading another app's secret from the Keychain: 1 plugin.** It runs
`security find-generic-password` to read another developer tool's OAuth credential, so the user
can reuse an existing subscription without pasting a key. Here the token goes to that tool's own
API, which is a legitimate convenience. But the same call is how a stealer would lift the token,
so the scanner reports it as MEDIUM, and as CRITICAL if a collector endpoint is present.

**Pipe-to-shell strings that are never executed: 6 plugins** (4 MEDIUM because the plugin can
spawn processes, 2 INFO). See above.

## What was not found

- **Client-side telemetry: 0.** No bundle calls an analytics SDK endpoint (PostHog, Mixpanel,
  Segment, Amplitude, GA, Sentry ingest, Plausible, Umami, Aptabase…). The few files containing
  those names were MCP-server directories, icon lists, an ad-blocker's domain list and a word
  list. The policy against client-side telemetry appears to be holding.
- **No CRITICAL or collector-endpoint finding of any kind** in 2.6 GB of plugin code.

## Trust-posture notes

- **570 of 2,426 (23.5%) are desktop-only**, and **135 (5.6%) import Node modules without
  declaring `isDesktopOnly`**. On mobile they fail at load. Not a security issue, but a sign
  of how much code assumes full Node access.
- **74 of 2,500 (3.0%) directory entries have no `main.js` in their latest release.** The
  directory points at the repo, not at a pinned artifact, so the next release decides what users
  install.

## Takeaways for Obsidian users

1. **Scan on update, not only on install.** `python obsidian_audit.py --vault ~/Notes` takes
   seconds. Run it before you click "Update all".
2. **Be most careful with plugins that combine vault reads, network and Node access.** 21.7%
   read the whole vault and talk to the network. Know where each of them sends your notes.
3. **Treat obfuscated plugins as unreviewable.** You can't tell what they do, whatever their
   intent.
4. **Prefer plugins whose capabilities match their description.** A word counter has no reason
   to spawn processes.

---

Reproduce: `python obsidian_audit.py --all --limit 1500 --json > scan.json`. Scan date
2026-11-24/25; latest releases at that time.

*Findings are pattern matches warranting human review, not verdicts. Report a suspected
malicious plugin to the Obsidian team and its author, not as a public accusation.*
