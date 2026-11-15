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
confirm with the user, who can then run the install themselves. No opinion: Codex and Copilot get no output, Cursor and
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
Other commands are not sent at all. alalanet does not store the command line.

**Environment.**
- `ALALANET_TOKEN`, or `ALALANET_TOKEN_FILE` naming a file that holds it (for device management): a plan token, sent
  as `Authorization: Bearer` and never printed. With it, the hook's daily limit is your plan's; without it, 1,000
  checks a day per client address. A token that cannot be used (an unreadable file, a bad character, plain http to
  another machine) holds installs and says why.
- `ALALANET_FAIL_CLOSED=1`: when alalanet cannot be reached or the daily limit is spent, hold the install. By default
  it goes ahead unchecked, with one line on stderr, as Claude Code does when its HTTP hook cannot be reached.
  Recommended for CI and sensitive organisations; keep `ALALANET_API` on https.

Known limits: input written to an already running process, a script written to disk and then run, and MCP tools that
run commands are not seen by this hook.

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
