package agentkit

// Independent re-review of SEC9-AGENT round 2 (fc8b708): the stream decoder's failure modes and cost
// (a slow link, a page that never ends, a gzip bomb, the worst page the server writes), what an unmarked
// message can still hide after flagLetters, and what cleaning every string of an answer changes.
// Untracked review file; the source holds no raw invisible character.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

// zz2Peak runs f and returns how long it took and the highest heap in use above the start, sampled
// every 2 ms.
func zz2Peak(f func()) (time.Duration, uint64) {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	start := time.Now()
	f()
	d := time.Since(start)
	close(stop)
	wg.Wait()
	p := peak.Load()
	if p < base {
		return d, 0
	}
	return d, p - base
}

func zz2MiB(n uint64) float64 { return float64(n) / (1 << 20) }

// A page that never ends, at full speed: blanks inside the list, one string that never closes, and a
// gzip stream that unpacks past the bound. Each is an error at maxMailPage (96 MiB); the time and the
// heap it took are logged.
func TestZZReviewR2EndlessPages(t *testing.T) {
	chunk := bytes.Repeat([]byte(" "), 1<<20)
	letters := bytes.Repeat([]byte("A"), 1<<20)
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = zw.Write([]byte(`{"messages":[`))
	for i := 0; i < 200; i++ {
		_, _ = zw.Write(chunk)
	}
	_, _ = zw.Write([]byte(`]}`))
	_ = zw.Close()
	cases := []struct {
		name  string
		serve func(w http.ResponseWriter, r *http.Request)
	}{
		{"blanks forever inside the list", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"messages":[`)
			for r.Context().Err() == nil {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}},
		{"one string that never closes", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"messages":["`)
			for r.Context().Err() == nil {
				if _, err := w.Write(letters); err != nil {
					return
				}
			}
		}},
		{fmt.Sprintf("gzip of %d bytes unpacking to 200 MiB", gz.Len()), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz.Bytes())
		}},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(c.serve))
		k := reader(srv)
		var msgs []Message
		var err error
		d, peak := zz2Peak(func() { msgs, _, _, err = k.ReadMail(context.Background(), 0, "") })
		t.Logf("%s: %d messages in %v, heap peak +%.0f MiB, err %v", c.name, len(msgs), d, zz2MiB(peak), err)
		if err == nil || msgs != nil {
			t.Errorf("%s: %d messages, %v", c.name, len(msgs), err)
		}
		srv.Close()
	}
}

// The worst page the server writes for an honest inbox under attack (199 wraps of 64 KiB of '<', each
// '<' six bytes, indented, and the honest message), the time and heap it takes.
func TestZZReviewR2WorstPageCost(t *testing.T) {
	senderSK, recipientSK := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	recipientPK, _ := nostr.GetPublicKey(recipientSK)
	junk := nostr.Event{Kind: 1059, CreatedAt: nostr.Now(), Content: strings.Repeat("<", 64<<10-600), Tags: nostr.Tags{{"p", recipientPK}}}
	_ = junk.Sign(nostr.GeneratePrivateKey())
	canonical, _ := json.Marshal(junk)
	honest := giftWrap(t, senderSK, recipientPK, "the honest message")
	honestJSON, _ := json.Marshal(honest)
	var page bytes.Buffer
	var raws []json.RawMessage
	for i := 0; i < 199; i++ {
		raws = append(raws, canonical)
	}
	raws = append(raws, honestJSON)
	enc := json.NewEncoder(&page)
	enc.SetEscapeHTML(true)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"messages": raws, "next_since": 1763100000, "next_after_id": honest.ID, "note": "x"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(page.Bytes()) }))
	defer srv.Close()
	k := &Kit{SK: recipientSK, PK: recipientPK, API: srv.URL, HTTP: srv.Client()}
	var msgs []Message
	var err error
	d, peak := zz2Peak(func() { msgs, _, _, err = k.ReadMail(context.Background(), 0, "") })
	t.Logf("a page of %.1f MiB as the server writes it: %d message in %v, heap peak +%.0f MiB, err %v", zz2MiB(uint64(page.Len())), len(msgs), d, zz2MiB(peak), err)
	if err != nil || len(msgs) != 1 {
		t.Errorf("%d messages, %v", len(msgs), err)
	}
	// The same through gzip, as Caddy sends it (encode zstd gzip): what crosses the link.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(page.Bytes())
	_ = zw.Close()
	t.Logf("the same page gzipped: %d bytes", gz.Len())
}

// After flagLetters, an unmarked message hides at most five letters (one regional flag's code), and
// the ideographic selectors none; otherwise it is marked. Table, then the fuzzer.
func zz2HiddenLetters(s string) int {
	text, _ := safe.Text(s)
	return letters(safe.Hidden(s)) - letters(safe.Hidden(text)) + letters(string(safe.IdeographicSelectors(s)))
}

func TestZZReviewR2UnmarkedHidesAtMostFive(t *testing.T) {
	fl := func(code string) string { return "\U0001F3F4" + zzTags(code) + "\U000E007F" }
	for _, c := range []struct {
		name, in string
		marked   bool
	}{
		{"five letters as one flag's code", "hi " + fl("sendk"), false},
		{"two flags of five", fl("sendk") + fl("eykey"), true},
		{"a flag and one more tag", fl("sendk") + zzTags("x"), true},
		{"England kept, then a flag of five", fl("gbeng") + fl("sendk"), false},
		{"a flag and an ideographic letter", fl("sendk") + "\U00004E00\U000E0151", true},
		{"a flag inside a selector run", "\U0001F600\U0000FE0F" + fl("ustx") + zzSelBytes("ab"), true},
		{"a flag whose code is cut by a ZWSP", "\U0001F3F4" + zzTags("us") + "\U0000200B" + zzTags("tx") + "\U000E007F", true},
		{"the cancel tag twice", fl("ustx") + "\U000E007F", false},
	} {
		_, n, instr := cleanMail(c.in)
		if instr != c.marked {
			t.Errorf("%s: hidden_instructions %v, want %v (removed %d, hidden letters %d)", c.name, instr, c.marked, n, zz2HiddenLetters(c.in))
		}
	}
}

func FuzzZZReviewR2UnmarkedHidesAtMostFive(f *testing.F) {
	for _, s := range []string{"\U0001F3F4\U000E0075\U000E0073\U000E0074\U000E0078\U000E007F", "x\U000E0041", "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F\U0001F3F4\U000E0075\U000E0073\U000E0063\U000E0061\U000E007F",
		"\U00004E00\U000E0151", "\U0001F600\U0000FE01\U0000FE02\U000E0141\U000E0142"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		text, n, instr := cleanMail(s)
		if l := zzLeak(text); l != "" {
			t.Fatalf("cleanMail(%+q) leaves %s", s, l)
		}
		if instr && n == 0 {
			t.Fatalf("cleanMail(%+q) marks with nothing removed", s)
		}
		if h := zz2HiddenLetters(s); !instr && h > 5 {
			t.Fatalf("cleanMail(%+q) leaves unmarked a message whose removed characters spell %d letters", s, h)
		}
	})
}

// An error's text: the start of a body that is not JSON is cut at 1000 bytes, but a JSON hint is passed
// whole, up to the 4 MiB read: a server (or an ALALANET_API elsewhere) fills the model's context with it.
func TestZZReviewR2ErrorHintUnbounded(t *testing.T) {
	k := reader(answering(t, http.StatusBadRequest, `{"error":"bad_request","hint":"`+strings.Repeat("a", 3<<20)+`"}`))
	_, err := k.Get(context.Background(), "/v1/agents/x")
	if err == nil || len(err.Error()) > 2000 {
		n := 0
		if err != nil {
			n = len(err.Error())
		}
		t.Errorf("an error hint of 3 MiB reaches the model as %d bytes of error text", n)
	}
}
