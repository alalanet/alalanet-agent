package repopolicy

import "testing"

// R14: packageTarget takes anything after a PyPI name that holds none of @:/\ — pip options included. Fails closed only
// if no caller ever passes such a target; a strict specifier grammar would make it fail closed by itself.
func TestReviewPyPITrailingOptions(t *testing.T) {
	org := mustParse(t, "version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: r, expires: 2027-06-01}\n")
	for _, tg := range []string{"pypi:acme-tools==1 --find-links .", "pypi:acme-tools -f vendor", "pypi:acme-tools==1 --no-index --find-links=vendor"} {
		if got := Decide([]Layer{{Source: Managed, Policy: org}}, "hold", Hold{Kind: Package, Targets: []string{tg}, Reasons: []string{"new_package"}}, now); got == Allow {
			t.Errorf("%q is covered", tg)
		}
	}
}
