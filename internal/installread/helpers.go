package installread

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"strings"
)

// Helpers the reader shares with the rest of the server (internal/app calls them by their old names, internal/app/
// installread.go). Moved here unchanged from internal/app (repoconfig.go and installcheck.go) in RT-1's second round,
// so the server and alalanet-agent read a line with one implementation; clip is a copy of internal/app's own.

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// decodeExact decodes JSON (with comments and trailing commas removed) as the clients read it:
// member names match exactly, duplicate names and invalid UTF-8 are errors. Go's encoding/json v1
// matched names case-insensitively with the last one winning, so {"command":"bash -c …",
// "COMMAND":"node server.js"} was judged as node while the client ran bash (plan v2, P0-4).
func decodeExact(b []byte, v any) error {
	return jsonv2.Unmarshal(jsonc(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))), v)
}

// launchLine joins a launch command and its arguments into a shell line for ParseInstallLine. A shell
// payload (sh -c "npx -y x") must stay readable as a command, so arguments are joined as they are.
func launchLine(command string, args []string) string {
	return strings.TrimSpace(command + " " + strings.Join(args, " "))
}

func launchBase(w string) string {
	if i := strings.LastIndexAny(w, `/\`); i >= 0 {
		w = w[i+1:]
	}
	return strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(w), ".cmd"), ".exe")
}

// stripVersion: "@scope/name@1.2.3" -> "@scope/name", "name@1" -> "name".
func stripVersion(name string) string {
	if i := strings.LastIndexByte(name, '@'); i > 0 {
		return name[:i]
	}
	return name
}

// shellQuote quotes a word for the line an MCP entry's command and args make: its args are separate
// words for the client (no shell), so a value with spaces must stay one word when the line is read.
func shellQuote(w string) string {
	if w != "" && !strings.ContainsAny(w, " \t\n'\"\\;|&()<>{}$`*?![]#~") {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'"'"'`) + "'"
}

// unreadCode maps what ParseInstallLine could not read to a fixed reason code.
func unreadCode(msg string) string {
	switch {
	case strings.Contains(msg, "custom registry"), strings.Contains(msg, "config file"):
		return "custom_registry"
	case strings.Contains(msg, "loads other code"):
		return "code_from_environment"
	case strings.Contains(msg, "from a variable"):
		return "variable_argument"
	case strings.Contains(msg, "does not close"):
		return "unclosed_quote"
	case strings.Contains(msg, "git or URL"), strings.Contains(msg, "GitHub shorthand"), strings.Contains(msg, "direct URL"), strings.Contains(msg, "deno module"):
		return "git_or_url"
	case strings.Contains(msg, "standard input"):
		return "stdin_arguments"
	case strings.Contains(msg, "command substitution"):
		return "command_substitution"
	case strings.Contains(msg, "encoded"):
		return "encoded_command"
	case strings.Contains(msg, "nested too deep"):
		return "nested_too_deep"
	case strings.Contains(msg, "more install targets"):
		return "several_packages"
	}
	return "unknown_install_form"
}

// jsonc turns JSON with comments and trailing commas (VS Code, Zed) into JSON. Two linear passes:
// comments out first, then trailing commas (a comma followed only by whitespace before } or ]). The
// old single pass searched ahead for "*/" after every comma, which made a 1 MiB file of ",/**/"
// cost seconds of CPU per request (deep review 2026-11-09, SEC-1).
func jsonc(b []byte) []byte {
	return dropTrailingCommas(stripJSONComments(b))
}

func stripJSONComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			for i += 2; i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/'); i++ {
			}
			i++ // an unclosed comment runs to the end of the file
		default:
			out = append(out, c)
		}
	}
	return out
}

func dropTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
