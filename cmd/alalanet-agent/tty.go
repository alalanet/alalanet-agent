package main

import (
	"crypto/rand"
	"io"
	"os"
	"runtime"
)

// The user's own terminal, shared by mcp-approve and policy-approve: each asks there, and pins only when the code it
// shows there is typed back.

// codeAlphabet: the code's letters, without those read alike (0 O 1 I L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// terminalCode is a random six-letter code to type back.
func terminalCode() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b)
}

// openTTY opens the user's terminal itself, not stdin or stdout (an agent's shell gives the command pipes).
func openTTY() (io.Reader, io.Writer, func(), error) {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, nil, nil, err
		}
		out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
		if err != nil {
			in.Close()
			return nil, nil, nil, err
		}
		return in, out, func() { in.Close(); out.Close() }, nil
	}
	t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	return t, t, func() { t.Close() }, nil
}
