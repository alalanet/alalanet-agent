# alalanet-agent

[![mcptry](https://mcptry.com/badge/com.alalanet/check)](https://mcptry.com/servers/com.alalanet/check)

Local signer and MCP server for [alalanet.com](https://alalanet.com), a free trust layer for AI agents.
Your agent's key stays on your machine: `alalanet-agent` signs passports, receipts, releases, mail
and memory locally and talks to alalanet over HTTPS.

- **Passport**: a Nostr key (secp256k1) kept in `~/.config/alalanet/key` (mode 0600).
- **Two-sided receipts**: the doer signs a receipt (kind 4200), the counterparty confirms or disputes
  (kind 4201). Reputation counts only confirmed work. Both land in a public transparency log.
- **Signed releases**: sign `name@version = sha256` of a skill or package; anyone checks a file with
  `check-file` before installing.
- **Mail and memory**: NIP-59 gift-wrapped mail, client-side encrypted memory.

## Install

Binaries for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64 and windows/amd64 are at
<https://alalanet.com/dl/> with `SHA256SUMS`. Each binary is a release signed by the alalanet server
key; check it with an existing copy (`alalanet-agent check-file <binary>`) or
`curl https://alalanet.com/v1/artifacts/<sha256>`.

From source (Go 1.27):

```sh
go install github.com/alalanet/alalanet-agent/cmd/alalanet-agent@latest
```

## Use

```sh
alalanet-agent init                 # create the key (once)
alalanet-agent whoami               # your public key and passport page
alalanet-agent check-file <file>    # who signed this file, any conflicts
alalanet-agent mcp                  # local MCP server (stdio)
alalanet-agent mcp-verify           # check the tools of every configured remote MCP server
alalanet-agent mcp-approve <name>   # accept a server's current tool set (asks on your terminal)
```

Claude Code: `claude mcp add alalanet-agent -- alalanet-agent mcp`. Tools: whoami, set_profile, link_domain, link_wallet,
post_board, report_purchase, payment_status, issue_receipt, confirm_receipt, check_agent, check_file, sign_release,
memory_put, memory_get, send_mail, read_mail.

`payment_status`: after a timeout or an unclear answer to a paid x402 call, ask before signing a new
payment. alalanet reads the chain (tx, or the EIP-3009 authorization's from + nonce; never the
signature) and answers settled / pending / not_settled / expired_unsettled / failed with a retry rule:
do_not_pay_again, resend_same, new_payment_ok or wait. No more paying twice.

Docker: `docker build -t alalanet-agent . && docker run -i -v alalanet-key:/home/agent/.config/alalanet alalanet-agent`
starts the stdio MCP server. The volume keeps the key between runs.

The remote, keyless checks need no install. `https://alalanet.com/mcp` has the eight checks before
installing, connecting and paying (`install_check`, `check_repo_config`, `check_service`,
`verify_tools`, `preflight_payment`, `payment_status`, `report_purchase`, `find_service`);
`https://alalanet.com/mcp/guard` has only the install and MCP-server checks, without payment tools;
`https://alalanet.com/mcp/full` has every tool.

## The install-time check in agent runtimes: `hook`

`alalanet-agent hook <runtime>` runs as an agent runtime's pre-tool command hook. When the agent is about to run a
shell command that installs or runs a package (npm, pnpm, yarn, bun, pip, uv, pipx and others, by the same reader
alalanet's server uses), it asks alalanet's `install_check` first and answers in the runtime's own format. Known
malicious packages are blocked, risky ones are held for the user, everything else goes on. Claude Code does not need
it: the alalanet plugin for Claude Code has its own HTTP hook.

| Runtime | Event | Matcher | File |
|---|---|---|---|
| Codex CLI (`codex`) | `PreToolUse` | `Bash` (unified exec matches as `Bash` too) | `~/.codex/hooks.json` or `<repo>/.codex/hooks.json` |
| Cursor (`cursor`) | `beforeShellExecution` **and** `preToolUse` | `Shell` on `preToolUse` | `.cursor/hooks.json` (`~/.cursor/hooks.json` for every project) |
| Copilot harness: VS Code, Copilot app, Copilot CLI (`copilot`) | `preToolUse` | — (only `bash` and `powershell` calls are read) | `.github/hooks/*.json` or `~/.copilot/hooks/` |
| Antigravity: app, CLI, IDE (`antigravity`) | `PreToolUse` | `run_command` | `.agents/hooks.json` or `~/.gemini/config/hooks.json` |

Give each hook a timeout of 30 seconds: the adapter waits up to 20 seconds for alalanet.

Cursor, `.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "alalanet-agent hook cursor", "timeout": 30 }],
    "preToolUse": [{ "command": "alalanet-agent hook cursor", "matcher": "Shell", "timeout": 30 }]
  }
}
```

Codex, `.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "alalanet-agent hook codex", "timeout": 30 }] }
    ]
  }
}
```

Codex runs a hook only after you review and trust its exact definition: open `/hooks` in Codex and trust the
alalanet hook once (again after any change to it). Until then nothing is checked, and nothing says so.

Copilot harness, `.github/hooks/alalanet.json`:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "type": "command", "bash": "alalanet-agent hook copilot", "powershell": "alalanet-agent hook copilot", "timeoutSec": 30 }
    ]
  }
}
```

Antigravity, `.agents/hooks.json`:

```json
{
  "alalanet-install-check": {
    "PreToolUse": [
      { "matcher": "run_command", "hooks": [{ "type": "command", "command": "alalanet-agent hook antigravity", "timeout": 30 }] }
    ]
  }
}
```

The runtimes run project hooks only in a trusted project or workspace. A hook file should call the installed, signed
binary by name, never download code to run it.

**What each answer means.** Block: deny, with the reason. Hold: Copilot asks the user (where no user can answer, as
in its cloud agent, it denies), Antigravity always asks (`force_ask`). Codex and Cursor cannot pause a call there, so a hold is a deny whose reason tells the agent to
confirm with the user, who can then run the install themselves. Codex starts a hook through your login shell
(`$SHELL -lc`), so anything your login profile prints lands on stdout before the answer, and Codex cannot read it:
`hook codex` therefore also ends a deny, and a hold, with exit code 2 and the reason alone on stderr, on which Codex
blocks whatever stdout holds (Claude Code and Cursor read exit 2 as a block too). Codex shows all of that stderr as the
reason, so the hook's other stderr lines are dropped then; without a block they go to stderr as before. No opinion: Codex and Copilot get no output, Cursor and
Antigravity an explicit `allow`, so the runtime's own approval rules still apply. An input the adapter cannot read is
held, never let through. The runtime's name is read in any case; a name the adapter does not know ends it with exit
code 2 and the usage, which blocks the call, so a typo in a hook file never lets installs through unchecked.

**Use each runtime's own hook file** (the table above). Cursor also runs Claude Code's hooks from
`.claude/settings.json`, and the Copilot harness reads that file too. Each adapter reads every runtime's input, but it
answers in its own runtime's form: `hook codex` answers in Claude Code's form, which Cursor reads as well; the Copilot
harness documents only its own form, so a deny printed in another form may be lost there. If a hook must live in
`.claude/settings.json`, use `alalanet-agent hook codex` and check it in each runtime that reads the file. Claude Code
itself needs no hook there: the alalanet plugin checks installs.

**What leaves the machine.** Only the command line, and only when it installs or runs a package. It goes as
`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"…"}}` to
`https://alalanet.com/v1/hooks/claude-code`, with `User-Agent: alalanet-agent/<version> (hook <runtime>)`. Your
working directory, file paths, session and conversation ids, transcript, model, e-mail and prompts are never sent.
A command held only for its shell syntax (a zsh glob group on a word), with no package in it to check, is held on
your machine with alalanet's own words and not sent. Other commands are not sent at all. alalanet does not store the
command line.

**Environment.**
- `ALALANET_TOKEN`, or `ALALANET_TOKEN_FILE` naming a file that holds it (for device management): a plan token, sent
  as `Authorization: Bearer` and never printed. With it, the hook's daily limit is your plan's; without it, 1,000
  checks a day per client address. A token that cannot be used (an unreadable file, a bad character, plain http to
  another machine) holds installs and says why.
- `ALALANET_FAIL_CLOSED=1`: when alalanet cannot be reached or the daily limit is spent, hold the install. By default
  it goes ahead unchecked, with one line on stderr, as Claude Code does when its HTTP hook cannot be reached.
  Recommended for CI and sensitive organisations; keep `ALALANET_API` on https.

**Policy exceptions and your shell startup files.** When an exception in your organisation's or repository's alalanet
policy would let a held install go, the hook first makes sure nothing moves where the package comes from — and your
shell's startup files (`~/.zshenv`, `~/.zshrc`, `~/.bashrc`, `~/.profile`, the zsh files of a `ZDOTDIR` your
`.zshenv` sets, `BASH_ENV`'s and `ENV`'s files, fish's config, `conf.d`, `functions` and `fish_variables`,
`environment.d`, the `/etc` ones and `/etc/paths.d`, Codex's shell snapshots), and the files they source by a path
or the programs they `eval` (such as `brew shellenv`), run before every command the agent starts. So the hook keeps a
pin of them: a sha256 of each file (never its contents) in `~/.local/state/alalanet/policy/startup-pin.json`
(`%LOCALAPPDATA%\alalanet\policy` on Windows), with a mark beside it and one in `~/.config/alalanet`. The first time,
they are pinned as they are, and the exception applies. Later, while they are unchanged, it still applies; once one of
them changes, appears or goes, or the pin is removed, the exception no longer covers holds and the hold names that
file. When you have looked at the change yourself, run `alalanet-agent policy-approve` in your own terminal: it shows
the changed paths and a code, and pins the files again when you type the code back. A new Codex shell snapshot is
pinned on first sight; one changed later, or written again under a name once pinned, is held like any other file.
fish's `fish_variables` is pinned by what changes commands (exported variables, `fish_user_paths`,
`fish_function_path`), not by a prompt's state. The hook holds any agent command that names
`policy-approve`, the pin, its folders or Codex's snapshots. The pin trusts what is there the first time, and it
stops a change after that — not a file that was already hostile at the start, a file sourced two levels down (such as
oh-my-zsh's `custom/*.zsh` and plugins) or by a path the hook cannot work out, or a local process that sets out to get
past it. A Codex snapshot carries whatever the shell had when the session started, including what such files set.
The package managers' own code is the user's to write as well (a global npm, a virtual environment's `bin/pip` and
`site-packages`, uv itself), and so are their caches (npm's `cache`): changing those is within the same limit, a
process that sets out to get past the check.

**Where the code is shown.** policy-approve opens the controlling terminal itself, never the command's input or
output, so a command an agent runs without a terminal cannot answer it. That is not true everywhere an agent runs
commands:
- Codex: its `exec_command` tool can run a command in a pseudo-terminal (`tty: true`) and type into it later
  (`write_stdin`), and the model reads that terminal's output;
- Cursor, GitHub Copilot in VS Code and Antigravity run the agent's commands in an editor terminal, which is very
  likely a pseudo-terminal whose screen the model reads (not verified for each);
- Claude Code's Bash tool has no controlling terminal (opening `/dev/tty` fails there).

Where the model can read the terminal, the code does not protect anything: what protects the pin there is the hook
holding the line that names policy-approve or the pin. Run policy-approve in a terminal of your own, outside the agent.

Known limits: input written to an already running process, a script written to disk and then run, and MCP tools that
run commands are not seen by this hook (the MCP check below looks at their definitions, not at what they run).
Of mise's configuration, three places are not read: `/etc/mise/config.toml` (mise's system config, with `system`
on), a config named by `MISE_CONFIG_FILE` or `MISE_GLOBAL_CONFIG_FILE` in the hook's own environment, and mise
settings a project's `.envrc` exports as `MISE_*` variables (for example `MISE_NODE_MIRROR_URL`).

## The MCP check: `mcp-verify`, `mcp-approve` and the MCP side of `hook`

The `hook` of every runtime checks an MCP server's tools at the first use of one of them, and again when the kept read
expires. `mcp-verify` checks every configured server and prints one line each; `mcp-approve <name>` accepts a
server's current tool set as this machine's.

| Runtime | Event and matcher for MCP tools | How the tool names its server |
|---|---|---|
| Claude Code (`claude-code`) | `PreToolUse`, matcher `mcp__.*` (a command hook) | `mcp_server`, or `mcp__<server>__<tool>` |
| Codex CLI (`codex`) | `PreToolUse`, matcher `^mcp__` | `mcp__<server>__<tool>` |
| Cursor (`cursor`) | `beforeMCPExecution` | `mcp_server_name` and the URL |
| Copilot harness (`copilot`) | `preToolUse` (or `PreToolUse`) | `<server>/<tool>` or `mcp__<server>__<tool>` (not documented: a name that fits no configured server, or two, has no opinion) |
| Antigravity (`antigravity`) | `PreToolUse` | `call_mcp_tool` with `ServerName`, or `mcp_<server>_<tool>` |

A hold is the runtime's own: Claude Code and the Copilot harness ask, Codex and Cursor deny with the reason (their ask
does not hold the call), Antigravity uses `force_ask`. A warning is Claude Code's `systemMessage` or Cursor's
`user_message`; Codex, the Copilot harness and Antigravity have no place for one, so it goes to stderr.

**The agent's own copy.** Cursor (`~/.cursor/projects/<project>/mcps/<server>/tools/`) and Antigravity
(`~/.gemini/antigravity/mcp/<server>/`) keep the tools the model reads on disk. alalanet-agent reads that copy too: it
pins it on this machine, holds when a known tool in it changes or it carries signs of instructions to the model, and
warns when its descriptions differ from alalanet-agent's own anonymous read. That covers servers alalanet-agent cannot
read itself (they need authorization, or run on this machine). The copy is not compared with alalanet's record yet.

**What it reads.** The servers you configured: Claude Code's `~/.claude.json` (or `$CLAUDE_CONFIG_DIR/.claude.json`;
read as a stream, only `mcpServers` and the projects of the session's folders kept; a file over 256 MiB is not read
and one stderr line says so) and the `.mcp.json` servers you approved in Claude Code; Cursor's `~/.cursor/mcp.json`;
Codex's `~/.codex/config.toml` (or `$CODEX_HOME`) and its trusted projects'; the Copilot harness's
`~/.copilot/mcp-config.json` and VS Code's `mcp.json`; Antigravity's `~/.gemini/config/mcp_config.json`. A project's
file never decides which URL a server you configured is checked at: a name your own file defines is checked at your
URL (with a warning when the project names it elsewhere). Codex's project file is read only when Codex trusts the
project, and then overrides as in Codex; a name only a project file has (or an unapproved `.mcp.json` server) is not
contacted at all, since alalanet-agent cannot tell that the runtime trusts that workspace. Each of these files is read only when it is a
regular file of 1 MiB at most.
alalanet-agent then reads each remote server's `tools/list` itself, anonymously, from your machine: its own client
name, none of your configured headers, no OAuth token, public addresses only, no redirect. A server that needs
authorization, runs on this machine, uses SSE or sits on a private network is not read, and has no opinion.

**What it sends to alalanet.** For each configured public server, the listing id of its address: a hash of the
address as alalanet catalogues it, without user info, fragment or a query that is not plain inputs; at most once per
server every 10 minutes (24 hours for one alalanet does not list). For a server alalanet lists, that id is the public
listing's id: **alalanet learns which listed server this address uses.** Nothing else: never the tool texts or names,
your headers or keys, the address as you configured it, your session, your working folder or the call's arguments.
A lookup that sends a 12-bit prefix only (k-anonymity) comes with a later server release.

**What it decides.** It holds (Claude Code asks, Cursor denies with the reason) when a known tool changed or gained
authority, against the set this machine accepted or the one the server serves alalanet, or when the descriptions
carry signs of instructions to the model; a difference you accepted with `mcp-approve` warns instead. It warns once a
session on more tools (signed-in users often see more), an older set, a per-user list, or a pinned server that stops
letting alalanet-agent read it. When it cannot check (a timeout, alalanet unreachable, its state locked or unreadable),
the call goes ahead with one stderr line; `ALALANET_FAIL_CLOSED=1` holds it instead. `ALALANET_MCP_UNVERIFIED=hold`
also holds servers that cannot be read by design. Its state is in `~/.cache/alalanet/mcp/state.json` (or
`$XDG_CACHE_HOME`, `%LOCALAPPDATA%`), 0600: tool names and digests only.

**Limits, plainly.** `mcp-approve` asks on your own terminal and pins only when you type back a code it shows there,
and the install hook holds a shell line that would run it. That stops a model that is not trying to get past it, not
a determined process on your machine: an agent with a shell and file access can give itself a terminal (a pty) or
edit the state file. The read is anonymous and alalanet-agent's own, so a server that answers clients differently can
show it a clean set; and a poisoned description is already in the model's context before the first tool call.

## The hosted MCP server `com.alalanet/check`

`https://alalanet.com/mcp` (listed in the official MCP Registry as `com.alalanet/check`) is hosted by
alalanet. This repository is its open client. You do not have to trust the server's word: verdicts,
live checks, status changes, receipts and releases are signed Nostr events written to a public
transparency log (<https://alalanet.com/transparency>), and inclusion proofs can be verified offline.

## Security

Report vulnerabilities privately through this repository's Security tab ("Report a vulnerability") or
to info@alalanet.com. Never paste your key into a chat or a prompt.

## License

Apache-2.0. This repository mirrors the client from the alalanet monorepo.
