package installread

import "strings"

// OwnShellAsk: the hook's answer to a line that names no install target and holds only for the own shell's reasons — a
// zsh group on a word, held although the line installs nothing (lineGroup, ADR-0159 round 38). It is the ask the
// server's hook gives for such a line, word for word ("alalanet install_check: NOT CHECKED. … Install only if the user
// confirms."), so alalanet-agent answers it on the machine and the line, which names no package to check, is not sent
// (round 39). A line with a target, or with any other reason of either reader, is not answered here.
func OwnShellAsk(line string) (reason string, ok bool) {
	targets, unread, _, subst := ParseLine(line)
	if len(targets) > 0 || len(unread) == 0 {
		return "", false
	}
	for _, u := range unread {
		if !strings.HasPrefix(u, whyOwnShell) {
			return "", false
		}
	}
	if len(HookExtra(line, targets, unread, subst)) > 0 {
		return "", false
	}
	return "alalanet install_check: NOT CHECKED. " + strings.Join(unread, "; ") + ". Install only if the user confirms.", true
}
