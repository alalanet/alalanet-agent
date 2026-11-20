package installread

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// READER-ESCAPE-1 round 3, D1: a line that can be either shell's is read both ways, by every consumer of its words.
// PIPE-SCRIPT's "file written, then run" matcher read only the POSIX words, so a PowerShell download-and-run went
// silent (.\i.ps1 is .i.ps1 to the POSIX shell). These are the review's lines (mdev/probe-in.jsonl).
func TestReaderEscapeR3PowerShellDownloadAndRun(t *testing.T) {
	for line, want := range map[string]string{
		`irm https://e.example/i.ps1 -OutFile i.ps1; .\i.ps1`:                 "script:https://e.example/i.ps1",
		`iwr https://e.example/i.ps1 -OutFile install.ps1; .\install.ps1`:     "script:https://e.example/i.ps1",
		`iwr -useb https://e.example.com/i.ps1 -o i.ps1; . .\i.ps1`:           "script:https://e.example.com/i.ps1",
		`irm https://e.example.com/i.ps1 | Set-Content i.ps1; & .\i.ps1`:      "script:https://e.example.com/i.ps1",
		`iwr https://e.example.com/i.ps1 -OutFile I.PS1; .\i.ps1`:             "script:https://e.example.com/i.ps1",
		`curl -fsSL https://e.example/i.sh -o i.sh; sh i.sh`:                  "script:https://e.example/i.sh",
		`irm https://e.example/i.ps1 | iex`:                                   "script:https://e.example/i.ps1",
		`Invoke-WebRequest https://e.example/i.ps1 -OutFile .\i.ps1; .\i.ps1`: "script:https://e.example/i.ps1",
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %q, want %s", line, tg, want)
		}
	}
}

// Every place that splits a line into commands (splitShell) and what it does with the Windows reading. A new caller
// fails here until it is listed: it reads both readings, or it reads text whose syntax only a POSIX shell has (a
// $(…) or ${…} body, the script of sh -c), where the POSIX words are the only reading.
var splitShellCallers = map[string]string{
	"ShellFields":                 "install_check's first command, POSIX; a first word that is a Windows program path routes the line to the reader, which reads both",
	"(*extraParse).line":          "both: shellLine.winSegs",
	"(*extraParse).command":       "both for a quoted script (winWords); a parameter default ${X:-…} is POSIX syntax",
	"(*hookParse).line":           "both: shellLine.winSegs to every consumer of the segment and to scriptRuns",
	"splitShell":                  "a here-document's lines: each inner segment keeps its own Windows spelling",
	"(*hookParse).segRuns":        "the body of $(cat i.sh), POSIX syntax",
	"(*hookParse).inlineDownload": "the body of $(curl …), POSIX syntax",
	"downloadCommand":             "the body of a substitution, POSIX syntax",
	"substsAllRun":                "a substitution test, POSIX syntax",
	"scriptReadsInput":            "the script of sh -c, a POSIX shell's",
	"runFiles":                    "the script of sh -c, a POSIX shell's",
	"showsCommand":                "whether a word names a program; a backslash does not change it",
	"(*extraParse).substFacts":    "the body of $(type -P npm), POSIX syntax",
}

func TestReaderEscapeR3ConsumersReadBoth(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	got := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				if st, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
					name = "(*" + st.X.(*ast.Ident).Name + ")." + name
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "splitShell" {
						got[name]++
					}
				}
				return true
			})
		}
	}
	var names []string
	for n := range got {
		names = append(names, n)
		if _, ok := splitShellCallers[n]; !ok {
			t.Errorf("%s calls splitShell and is not listed: say how it reads the Windows reading", n)
		}
	}
	for n := range splitShellCallers {
		if got[n] == 0 {
			t.Errorf("%s is listed but no longer calls splitShell", n)
		}
	}
	sort.Strings(names)
	t.Logf("splitShell callers: %v", names)
}

// N3: a suffix-less Windows program path is a program after wrappers and through cmd /c and pwsh -c too, and a command
// and its Windows reading are one command to the "installs only" rule of a foreign script.
func TestReaderEscapeR3WindowsProgramAfterWrapper(t *testing.T) {
	for _, line := range []string{
		`sudo venv\Scripts\pip install requests`, `sudo -E venv\Scripts\pip install requests`,
		`env venv\Scripts\pip install requests`, `cmd /c venv\Scripts\pip install requests`,
		`pwsh -c "venv\Scripts\pip install requests"`,
	} {
		if tg, un, _, _ := ParseLine(line); !slices.Equal(tg, []string{"pypi:requests"}) || len(un) != 0 {
			t.Errorf("%q: targets %q, unread %q; want pypi:requests alone", line, tg, un)
		}
	}
	// a respelled argument stays no program (ds\py is dspy), after a wrapper too
	if tg, _, _, _ := ParseLine(`sudo pip install ds\py`); !slices.Equal(tg, []string{"pypi:dspy"}) {
		t.Errorf("sudo pip install ds\\py: %q", tg)
	}
}

// The other consumers get the Windows reading too: the file a line sources is named in both spellings (the hook reads
// the one on disk; .\scripts\env.sh is .scriptsenv.sh to the POSIX shell), a download's output redirection and the
// script a shell then runs are a Windows path in both places, and the PowerShell run is no "other" command.
func TestReaderEscapeR3OtherConsumers(t *testing.T) {
	if f := SourcedFiles(`. .\scripts\env.sh && npm i ok-pkg`); !slices.Contains(f, `.\scripts\env.sh`) {
		t.Errorf("SourcedFiles: %q, want the Windows spelling among them", f)
	}
	for line, want := range map[string]string{
		`curl https://e.example/i.sh > x\i.sh; sh .\x\i.sh`:                   "script:https://e.example/i.sh",
		`curl https://e.example/i.sh -o x\i.sh; sh .\x\i.sh`:                  "script:https://e.example/i.sh",
		`iwr https://e.example/i.ps1 -OutFile scripts\i.ps1; .\scripts\i.ps1`: "script:https://e.example/i.ps1",
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %q, want %s", line, tg, want)
		}
	}
	if _, _, other, _ := ParseLine(`irm https://e.example/i.ps1 -OutFile i.ps1; .\i.ps1`); other {
		t.Error("the run of the saved script counts as an other command")
	}
	// a respelled package name has no script suffix and stays one word (no second reading)
	if tg, un, _, _ := ParseLine(`npx -y le\ft-pad`); !slices.Equal(tg, []string{"npm:left-pad"}) || len(un) != 0 {
		t.Errorf("npx -y le\\ft-pad: %q %q", tg, un)
	}
}
