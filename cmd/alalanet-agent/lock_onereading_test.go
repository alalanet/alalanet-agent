package main

import (
	"testing"
)

// npm and bun read their lock files by exact names, the last of a repeated name whole; encoding/json folded names,
// so "resolved":"<a git URL>","re<U+017F>olved":"<the registry's tarball>" was the registry's tarball to
// alalanet-agent and the git URL to npm (the batch P3 review's P2-1, as a class).
func TestLockFilesReadAsNpmReadsThem(t *testing.T) {
	const good = "https://registry.npmjs.org/acme-cli/-/acme-cli-1.0.0.tgz"
	for name, lock := range map[string]string{
		"resolved, long s":    `{"packages":{"node_modules/acme-cli":{"version":"1.0.0","resolved":"git+https://evil.example/x.git","re` + "\u017f" + `olved":"` + good + `"}}}`,
		"link, kelvin":        `{"packages":{"node_modules/acme-cli":{"version":"1.0.0","resolved":"` + good + `","link":true,"lin` + "\u212a" + `":false}}}`,
		"packages reset":      `{"packages":{"node_modules/acme-cli":{"version":"1.0.0","resolved":"git+https://evil.example/x.git"}},"Packages":null}`,
		"v1 tree, Resolved":   `{"dependencies":{"acme-cli":{"version":"1.0.0","resolved":"git+https://evil.example/x.git","Resolved":"` + good + `"}}}`,
		"v1 tree, deps reset": `{"dependencies":{"acme-cli":{"version":"1.0.0","resolved":"git+https://evil.example/x.git"}},"DEPENDENCIES":{}}`,
	} {
		c := &regCheck{npmNames: map[string]bool{"acme-cli": true}}
		c.npmLock("package-lock.json", []byte(lock))
		if c.why == "" {
			t.Errorf("%s: the lock npm installs from outside the registry passed", name)
		}
	}
	c := &regCheck{npmNames: map[string]bool{"acme-cli": true}}
	c.npmLock("package-lock.json", []byte(`{"packages":{"node_modules/acme-cli":{"version":"1.0.0","resolved":"`+good+`","Note":1}}}`))
	if c.why != "" {
		t.Fatalf("a plain lock: %s", c.why)
	}
	c = &regCheck{npmNames: map[string]bool{"acme-cli": true}}
	c.bunLock("bun.lock", []byte(`{"packages":{"acme-cli":["acme-cli@github:evil/x",""]},"pac`+"\u212a"+`ages":{"acme-cli":["acme-cli@1.0.0",""]},}`))
	if c.why == "" {
		t.Error("bun.lock: the entry bun reads passed")
	}
}
