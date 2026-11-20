package main

// REPO-POL-NPMRC round 7 (ADR-0174 round 12): the activate templates a sourced script must be, and how a script is
// matched to one. A template is the bytes a tool writes, with the venv's path as @VENV@ and the prompt as @PROMPT@ at
// the places it writes them (activate/, embedded; activateTemplates lists each file's sha256). A script matches a
// template when, read from its first byte to its last, it is the template's bytes with a value at each of those
// places and nothing else anywhere — the invariants:
//
//  1. the values carry no shell syntax: the venv's path is from a safe set (letters, digits, / . _ - + @ ~, and a space
//     only where the template quotes every place it puts the path), at most maxVenvPath bytes; the prompt is from
//     [A-Za-z0-9._-], at most maxPrompt bytes; every place of a field has the same value;
//  2. the values stand only at the template's places: the rest of the script is the template's own bytes, so the path
//     or the prompt anywhere else is a byte the template does not have;
//  3. one venv: the path the script names must resolve to the very folder the script is in (the folder above its bin,
//     resolved) — not a link's target named in its place, not another folder;
//  4. byte for byte: no folding of white space or line ends, no byte-order mark, nothing after the template's last
//     byte.

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed activate
var activateFS embed.FS

// activateTemplates: the sha256 of each template file, by the tool and version that writes it (made offline; uv's is
// virtualenv's template, per its header).
var activateTemplates = map[string]string{
	"445276dbd67921cfdf87ff42a93620bdb72d14d54bd937186ca04b241e8ece5d": "uv 0.13.7",
	"e892f9f11b3c3a320820e20f674957f2f88d3435c83123f68aa986c142971fdd": "uv 0.13.7, a prompt",
	"c0d04571ed2438a5735c9d5f1f4d4697abdca74481f1250e85e08d8c1b76c1e3": "uv 0.13.7, relocatable",
	"9665d9bb5d3dbae59cc9d2498ff086c9b997c498129b2de206db92005da51329": "uv 0.13.7, relocatable, a prompt",
	"3070724778d28bbcf633df9e264388b8946facc8d52904033a4ea026e1067e08": "CPython 3.9.6 venv",
	"9db7882a9518de66d6f02c04483167ff6d068f07e3ee0f4779431b349eb7ffe6": "CPython 3.12.14 venv",
	"778854d6497e3cff8f366cfd92b49a0af7db339cadf9310957bd673c3dff092a": "CPython 3.13.18, 3.14.7 and 3.15.2 venv",
}

const (
	maxVenvPath = 1024 // bytes of a venv's path a template takes
	maxPrompt   = 128  // bytes of a prompt
)

// tmplPart is a template's literal bytes, or one of its fields (@VENV@, @PROMPT@).
type tmplPart struct {
	lit   []byte
	field string // "", "VENV" or "PROMPT"
}

type template struct {
	name       string
	parts      []tmplPart
	venvQuoted bool // every place of @VENV@ stands inside quotes: a space may be in the path
}

// templates: the embedded files whose sha256 activateTemplates lists, parsed into parts, each set of bytes once (the
// CPython 3.13, 3.14 and 3.15 files are one template); a file it does not list is not used.
var templates = func() []template {
	ents, _ := activateFS.ReadDir("activate")
	var out []template
	parsed := map[string]bool{}
	for _, e := range ents {
		b, err := activateFS.ReadFile("activate/" + e.Name())
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		name, ok := activateTemplates[h]
		if !ok || parsed[h] {
			continue
		}
		parsed[h] = true
		out = append(out, parseTemplate(name, b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}()

func parseTemplate(name string, b []byte) template {
	t := template{name: name, venvQuoted: true}
	for len(b) > 0 {
		iv, ip := bytes.Index(b, []byte("@VENV@")), bytes.Index(b, []byte("@PROMPT@"))
		i, field, n := -1, "", 0
		switch {
		case iv >= 0 && (ip < 0 || iv < ip):
			i, field, n = iv, "VENV", len("@VENV@")
		case ip >= 0:
			i, field, n = ip, "PROMPT", len("@PROMPT@")
		}
		if i < 0 {
			t.parts = append(t.parts, tmplPart{lit: b})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, tmplPart{lit: b[:i]})
		}
		if field == "VENV" && !(i > 0 && i+n < len(b) && (b[i-1] == '\'' || b[i-1] == '"') && b[i+n] == b[i-1]) {
			t.venvQuoted = false
		}
		t.parts = append(t.parts, tmplPart{field: field})
		b = b[i+n:]
	}
	return t
}

func venvByte(c byte, quoted bool) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("/._-+@~", c) >= 0 || quoted && c == ' '
}

func promptByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// match: the values of a script's fields when it is t's bytes with them at t's places (invariants 1, 2 and 4), or ok
// false.
func (t template) match(b []byte) (venv, prompt string, ok bool) {
	values := map[string]string{}
	pos := 0
	for _, p := range t.parts {
		if p.field == "" {
			if !bytes.HasPrefix(b[pos:], p.lit) {
				return "", "", false
			}
			pos += len(p.lit)
			continue
		}
		end, max := pos, maxPrompt
		if p.field == "VENV" {
			max = maxVenvPath
		}
		for end < len(b) && (p.field == "VENV" && venvByte(b[end], t.venvQuoted) || p.field == "PROMPT" && promptByte(b[end])) {
			end++
		}
		v := string(b[pos:end])
		if v == "" || len(v) > max {
			return "", "", false
		}
		if prev, seen := values[p.field]; seen && prev != v {
			return "", "", false
		}
		values[p.field] = v
		pos = end
	}
	return values["VENV"], values["PROMPT"], pos == len(b)
}

// activateTemplate: the name of the template a sourced script is, or "". The script must be <venv>/bin/activate, its
// bytes a template's with values at the template's places (template.match), and the path it names must resolve to
// the folder it is in (invariant 3); a template without @VENV@ (uv's relocatable one) works out its venv from its own
// place, so the folder it is in is its venv.
func activateTemplate(path string, b []byte) string {
	if filepath.Base(filepath.Dir(path)) != "bin" {
		return ""
	}
	own, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(path)))
	if err != nil {
		return ""
	}
	for _, t := range templates {
		venv, _, ok := t.match(b)
		if !ok {
			continue
		}
		if venv == "" { // no @VENV@ in the template
			return t.name
		}
		if !filepath.IsAbs(venv) || filepath.Clean(venv) != venv {
			continue
		}
		if r, err := filepath.EvalSymlinks(venv); err == nil && r == own {
			return t.name
		}
	}
	return ""
}
