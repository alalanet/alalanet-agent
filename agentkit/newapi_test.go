package agentkit

// SEC9-AGENT rounds 2 and 3: the tests that use what a round adds (MemoryRead, maxMailPage, Shown); the
// others of the rounds are in answers_test.go and round3_test.go and run on the code before them too.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// Round 3: Shown cleans, then cuts at a character's start past max bytes, and marks the cut.
func TestShown(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"one past the bound", 17, "one past the boun (cut)"},
		{"ab" + hiddenTags("xyz") + "cd", 4, "abcd"},
		{strings.Repeat("\U000000E9", 5), 5, "\U000000E9\U000000E9 (cut)"},
		{"\U0001F600\U0001F600", 6, "\U0001F600 (cut)"},
		{"", 0, ""},
	} {
		got := Shown(c.in, c.max)
		if got != c.want || !utf8.ValidString(got) {
			t.Errorf("Shown(%+q, %d) = %+q, want %+q", c.in, c.max, got, c.want)
		}
	}
}

// MemoryRead marks what MemoryGet cleans: none on an honest value, the count and hidden_instructions
// on one whose tags spell a word.
func TestMemoryReadMarks(t *testing.T) {
	var stored atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			stored.Store(string(b))
			_, _ = w.Write([]byte(`{"id":"x"}`))
		default:
			ev, _ := stored.Load().(string)
			fmt.Fprintf(w, `{"key":"k","expires_at":0,"event":%s}`, ev)
		}
	}))
	defer srv.Close()
	k := reader(srv)
	if _, err := k.MemoryPut(context.Background(), "k", "step 3 of 7", 0); err != nil {
		t.Fatal(err)
	}
	m, err := k.MemoryRead(context.Background(), "k")
	if err != nil || m.Key != "k" || m.HiddenRemoved != 0 || m.HiddenInstructions {
		t.Errorf("MemoryRead of an honest value: %+v %v", m, err)
	}
	if _, err := k.MemoryPut(context.Background(), "k", "ok"+hiddenTags("go"), 0); err != nil {
		t.Fatal(err)
	}
	if m, err := k.MemoryRead(context.Background(), "k"); err != nil || m.Value != "ok" || m.HiddenRemoved != 2 || !m.HiddenInstructions {
		t.Errorf("MemoryRead of a value with hidden tags: %+v %v", m, err)
	}
}

// The page bound: a page of exactly maxMailPage bytes is read; one byte more is an error that names
// the bound (the bound is lowered here; it is 96 MiB).
func TestReadMailPageBound(t *testing.T) {
	body := `{"messages":[],"next_since":5,"next_after_id":""}`
	defer func(old int64) { maxMailPage = old }(maxMailPage)
	for _, c := range []struct {
		pad int
		ok  bool
	}{{0, true}, {1, false}} {
		maxMailPage = int64(len(body))
		k := reader(answering(t, http.StatusOK, body+strings.Repeat(" ", c.pad)))
		_, ns, _, err := k.ReadMail(context.Background(), 0, "")
		switch {
		case c.ok && (err != nil || ns != 5):
			t.Errorf("a page of the bound's size: %d, %v", ns, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf("longer than %d bytes", maxMailPage))):
			t.Errorf("a page a byte past the bound: %v", err)
		}
	}
}

// Round 3: capped reads no byte past either bound, even when asked for more, and says which bound it
// met only when there was more to read; mark gives the element its whole budget again.
func TestCappedReadsNoBytePastItsBounds(t *testing.T) {
	read := func(c *capped, ask int) (int, error) { return c.Read(make([]byte, ask)) }
	c := &capped{r: strings.NewReader(strings.Repeat("x", 100)), left: 50, element: 10}
	if n, err := read(c, 64); n != 10 || err != nil {
		t.Fatalf("a read asked for more than the element's budget: %d bytes, %v", n, err)
	}
	c.mark()
	if n, err := read(c, 64); n != 10 || err != nil {
		t.Fatalf("a read after a mark: %d bytes, %v", n, err)
	}
	if n, err := read(c, 64); n != 0 || err != io.EOF || !c.long || c.over {
		t.Fatalf("at the element's bound with more to read: %d, %v, long %v, over %v", n, err, c.long, c.over)
	}
	c = &capped{r: strings.NewReader(strings.Repeat("x", 10)), left: 50, element: 10}
	_, _ = read(c, 64)
	if n, err := read(c, 64); n != 0 || err != io.EOF || c.long || c.over {
		t.Fatalf("an answer that ends at the element's bound is no overflow: %d, %v, long %v, over %v", n, err, c.long, c.over)
	}
	c = &capped{r: strings.NewReader(strings.Repeat("x", 30)), left: 30, element: 100}
	if n, _ := read(c, 64); n != 30 {
		t.Fatalf("a whole small answer: %d bytes", n)
	}
	if n, err := read(c, 64); n != 0 || err != io.EOF || c.over || c.long {
		t.Fatalf("an answer that ends at the page's bound is no overflow: %d, %v, over %v, long %v", n, err, c.over, c.long)
	}
	c = &capped{r: strings.NewReader(strings.Repeat("x", 31)), left: 30, element: 100}
	_, _ = read(c, 64)
	if _, err := read(c, 64); err != io.EOF || !c.over || c.long {
		t.Fatalf("a byte past the page's bound: %v, over %v, long %v", err, c.over, c.long)
	}
}
