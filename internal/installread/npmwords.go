package installread

import (
	"slices"
	"strings"
)

// READER-NPM-ABBREV-1 (ADR-0159 round 12): npm's option words as npm reads them. nopt expands a shorthand (--reg, -C),
// a cluster of one-letter shorthands (-sc: --loglevel silent --call) and an unambiguous prefix of a config key
// (--script-s is --script-shell, --node-o is --node-options; npm 10.8.2), and the second reader matched lever keys by
// their full name only: npm i x --script-s=./x.sh was silent where the full spelling held. npm 11 warns on a prefix;
// npm 12 refuses it (EUNKNOWNCONFIG). The keys and shorthands of each version are npmopts_gen.go's.

// npmShorthand is one CLI shorthand of npmShorthands.
type npmShorthand struct {
	in   uint8  // the versions that have it (bit i: npmVersions[i])
	keys string // the keys its expansion sets, space-separated (local: global, from --no-global)
}

// npmOptionKeys: the config keys npm sets for an option word as typed (--name, --name=v, a one-dash -name, -x) in any
// of the versions npmopts_gen.go holds, sorted: the word's own name when no version reads it as another key (nopt sets
// an unknown name as it is), none for a word that only a refusing version would read.
func npmOptionKeys(word string) []string {
	name, _, _ := strings.Cut(strings.TrimLeft(word, "-"), "=")
	var out []string
	for i := range npmVersions {
		for _, k := range npmResolve(uint8(1)<<i, name) {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}

// npmResolve: the keys nopt (resolveShort, then parse) sets for option name w in the version of bit v. resolveShort:
// an exact key goes on; an exact shorthand, then a cluster of one-letter shorthands, gives their keys; where w is no
// key's unambiguous prefix, a shorthand's unambiguous prefix gives that shorthand's keys. Then every leading "no-" is
// taken off (in any case) and w is a key or a key's unambiguous prefix. A version that refuses prefixes (npmStrict)
// reads neither prefix: nil. tools/installread_npmopts.js checks this reading against nopt for every prefix of every
// key and shorthand, with and without "no-", and every cluster of up to three letters.
func npmResolve(v uint8, w string) []string {
	strict := npmStrict&v != 0
	if npmConfigKeys[w]&v == 0 {
		if s, ok := npmShorthands[w]; ok && s.in&v != 0 {
			return strings.Fields(s.keys)
		}
		if c := npmCluster(v, w); c != nil {
			return c
		}
		if npmUnique(v, w) == "" {
			if s := npmShortPrefix(v, w); s != "" {
				if strict {
					return nil
				}
				return strings.Fields(npmShorthands[s].keys)
			}
		}
	}
	for len(w) >= 3 && strings.EqualFold(w[:3], "no-") {
		w = w[3:]
	}
	if npmConfigKeys[w]&v != 0 {
		return []string{w}
	}
	if k := npmUnique(v, w); k != "" {
		if strict {
			return nil
		}
		return []string{k}
	}
	return []string{w}
}

// npmCluster: the keys of w's letters when each is a one-letter shorthand of version v (nopt's singleCharacters), else
// nil.
func npmCluster(v uint8, w string) []string {
	if w == "" {
		return nil
	}
	var out []string
	for i := 0; i < len(w); i++ {
		s, ok := npmShorthands[w[i:i+1]]
		if !ok || s.in&v == 0 {
			return nil
		}
		for _, k := range strings.Fields(s.keys) {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}

// npmUnique: the one config key of version v that begins with w, or "" (abbrev's reading: none, or more than one).
func npmUnique(v uint8, w string) string {
	found := ""
	for k, in := range npmConfigKeys {
		if in&v != 0 && strings.HasPrefix(k, w) {
			if found != "" {
				return ""
			}
			found = k
		}
	}
	return found
}

// npmShortPrefix: the one shorthand of version v whose name begins with w, or "".
func npmShortPrefix(v uint8, w string) string {
	found := ""
	for k, s := range npmShorthands {
		if s.in&v != 0 && strings.HasPrefix(k, w) {
			if found != "" {
				return ""
			}
			found = k
		}
	}
	return found
}

// npmNegated: whether nopt reads option name w (dashes off) as negated: an odd number of leading "no-", in any case.
func npmNegated(w string) bool {
	neg := false
	for len(w) >= 3 && strings.EqualFold(w[:3], "no-") {
		neg, w = !neg, w[3:]
	}
	return neg
}

// npmValueOption: whether npm takes the next word as the value of an option word that names one key, whose type
// takes a word (pmLongValueOptions), through a prefix or a shorthand (--wor x: --workspace x). A negated or an
// --opt=value word takes none.
func npmValueOption(x string) bool {
	name := strings.TrimLeft(x, "-")
	if strings.Contains(x, "=") || npmNegated(name) {
		return false
	}
	ks := npmOptionKeys(x)
	return len(ks) == 1 && pmLongValueOptions["npm"]["--"+ks[0]]
}
