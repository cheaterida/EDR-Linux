package eventlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func writeWithChain(t *testing.T, path string, key []byte, n int) {
	t.Helper()
	logger, err := NewWithOptions(path, Options{
		MaxBytes: 0,
		Integrity: IntegrityOptions{
			EnableChain: true,
			Key:         key,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := logger.Write(Event{EventID: "evt-" + itoa(i), Category: "process", Severity: "low", Action: "observe", Decision: "alert"}); err != nil {
			t.Fatal(err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	var out []Event
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range splitLines(raw) {
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal: %v\nline=%q", err, line)
		}
		out = append(out, e)
	}
	return out
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func TestChainWriteAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 5)

	evts := readEvents(t, path)
	if len(evts) != 5 {
		t.Fatalf("expected 5 events, got %d", len(evts))
	}
	for i, e := range evts {
		if e.IntegrityVersion != IntegrityVersion {
			t.Fatalf("event %d missing integrity version", i)
		}
		if e.Seq != uint64(i+1) {
			t.Fatalf("event %d seq = %d, want %d", i, e.Seq, i+1)
		}
		if e.Hash == "" || e.HMAC == "" {
			t.Fatalf("event %d missing hash/hmac", i)
		}
		if i > 0 && e.PrevHash != evts[i-1].Hash {
			t.Fatalf("event %d prev_hash = %q, want %q", i, e.PrevHash, evts[i-1].Hash)
		}
	}
	res, err := Verify(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("verify reported issues: %+v", res.Issues)
	}
	if res.LastSeq != 5 || res.ChainLines != 5 || res.LegacyLines != 0 {
		t.Fatalf("unexpected counts: %+v", res)
	}
}

func TestChainDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 3)

	// Mutate the severity of the second event — that invalidates its hash.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(raw)
	if len(lines) < 2 {
		t.Fatalf("expected ≥2 lines")
	}
	var e Event
	if err := json.Unmarshal(lines[1], &e); err != nil {
		t.Fatal(err)
	}
	e.Subject = map[string]any{"injected": "evil"}
	mutated, _ := json.Marshal(&e)
	lines[1] = mutated
	out := concatLines(lines)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("verify accepted tampered file")
	}
	if len(res.Issues) == 0 || res.Issues[0].Kind != "hash_mismatch" {
		t.Fatalf("expected hash_mismatch issue, got %+v", res.Issues)
	}
}

func TestChainDetectsReorder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 3)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(raw)
	lines[0], lines[2] = lines[2], lines[0]
	if err := os.WriteFile(path, concatLines(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("verify accepted reordered file")
	}
	hasBreak := false
	for _, issue := range res.Issues {
		if issue.Kind == "prev_hash_break" || issue.Kind == "hash_mismatch" {
			hasBreak = true
		}
	}
	if !hasBreak {
		t.Fatalf("expected reorder to surface, got %+v", res.Issues)
	}
}

func TestLegacySegmentDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	// Pre-seed two v0.1 lines (no integrity fields).
	v01 := []byte(`{"schema_version":"v0.1","timestamp":"2026-01-01T00:00:00Z","event_id":"old-1","category":"process","severity":"low","action":"observe","decision":"alert"}` + "\n" +
		`{"schema_version":"v0.1","timestamp":"2026-01-01T00:00:01Z","event_id":"old-2","category":"file","severity":"low","action":"observe","decision":"alert"}` + "\n")
	if err := os.WriteFile(path, v01, 0o600); err != nil {
		t.Fatal(err)
	}
	// Now append via the chain-enabled logger.
	writeWithChain(t, path, key, 2)

	res, err := Verify(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("verify with legacy prefix should still be ok: %+v", res.Issues)
	}
	if res.LegacyLines != 2 {
		t.Fatalf("legacy lines = %d, want 2", res.LegacyLines)
	}
	if res.ChainLines != 2 {
		t.Fatalf("chain lines = %d, want 2", res.ChainLines)
	}
	if len(res.LegacySegment) != 1 || res.LegacySegment[0].Count != 2 {
		t.Fatalf("legacy segment mismatch: %+v", res.LegacySegment)
	}
	if res.LastSeq != 2 {
		t.Fatalf("last seq = %d, want 2", res.LastSeq)
	}
}

func TestVerifyWithoutKeyAcceptsHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 3)

	// No key provided: HMAC cannot be checked but the chain hash still
	// must validate. We surface this by accepting the file but flagging
	// each event's HMAC as unverifiable in the metrics. (For the
	// minimum contract tested here, OK is true iff the chain holds.)
	res, err := Verify(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("verify with nil key should still pass on hash: %+v", res.Issues)
	}
	if res.HasHMACKey {
		t.Fatalf("HasHMACKey should be false when no key supplied")
	}
}

func TestChainStatePersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	statePath := path + ".state"
	key := newTestKey(t)

	logger, err := NewWithOptions(path, Options{Integrity: IntegrityOptions{EnableChain: true, Key: key, StatePath: statePath}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.Write(Event{EventID: "first-" + itoa(i), Category: "process", Action: "observe", Decision: "alert"}); err != nil {
			t.Fatal(err)
		}
	}
	first := logger.ChainSnapshot()
	if first.LastSeq != 3 || first.ChainID == "" {
		t.Fatalf("first writer state bad: %+v", first)
	}
	// Re-open with the same options; the new chain writer must pick up
	// the persisted state and continue the sequence from 4.
	logger2, err := NewWithOptions(path, Options{Integrity: IntegrityOptions{EnableChain: true, Key: key, StatePath: statePath}})
	if err != nil {
		t.Fatal(err)
	}
	if err := logger2.Write(Event{EventID: "second-0", Category: "process", Action: "observe", Decision: "alert"}); err != nil {
		t.Fatal(err)
	}
	second := logger2.ChainSnapshot()
	if second.LastSeq != 4 {
		t.Fatalf("second writer seq = %d, want 4", second.LastSeq)
	}
	if second.ChainID != first.ChainID {
		t.Fatalf("chain id changed across restart: %q vs %q", second.ChainID, first.ChainID)
	}
}

func TestHMACFieldEqualsManual(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 1)

	evts := readEvents(t, path)
	if len(evts) != 1 {
		t.Fatalf("expected 1 event")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(evts[0].Hash))
	want := hex.EncodeToString(mac.Sum(nil))
	if want != evts[0].HMAC {
		t.Fatalf("HMAC mismatch: want %s got %s", want, evts[0].HMAC)
	}
}

func TestVerifyEmptyFileIsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	res, err := Verify(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("empty file should verify clean: %+v", res)
	}
}

func TestVerifyMissingFileIsOK(t *testing.T) {
	res, err := Verify(filepath.Join(t.TempDir(), "absent.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("missing file should verify clean: %+v", res)
	}
}

func TestChainIDStableAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	statePath := path + ".state"
	key := newTestKey(t)

	l1, _ := NewWithOptions(path, Options{Integrity: IntegrityOptions{EnableChain: true, Key: key, StatePath: statePath}})
	_ = l1.Write(Event{EventID: "x", Category: "process", Action: "observe", Decision: "alert"})
	id1 := l1.ChainSnapshot().ChainID
	l2, _ := NewWithOptions(path, Options{Integrity: IntegrityOptions{EnableChain: true, Key: key, StatePath: statePath}})
	if id2 := l2.ChainSnapshot().ChainID; id2 != id1 {
		t.Fatalf("chain id changed: %s vs %s", id1, id2)
	}
}

func TestNoChainBackCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger, err := New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(Event{EventID: "v01", Category: "process", Action: "observe", Decision: "alert"}); err != nil {
		t.Fatal(err)
	}
	evts := readEvents(t, path)
	if len(evts) != 1 {
		t.Fatalf("expected 1 event")
	}
	if evts[0].IntegrityVersion != "" || evts[0].Hash != "" {
		t.Fatalf("legacy write should not populate chain fields: %+v", evts[0])
	}
}

func TestTamperOnUnkeyedFileStillCaughtByHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 2)

	raw, _ := os.ReadFile(path)
	lines := splitLines(raw)
	var e Event
	_ = json.Unmarshal(lines[0], &e)
	e.Subject = map[string]any{"x": "y"}
	mutated, _ := json.Marshal(&e)
	lines[0] = mutated
	_ = os.WriteFile(path, concatLines(lines), 0o600)

	// Even without the key, hash mismatch must be reported.
	res, err := Verify(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("hash tamper missed without key")
	}
}

func concatLines(lines [][]byte) []byte {
	var out []byte
	for i, l := range lines {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, l...)
	}
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out
}

func TestVerifyOneValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 1)

	evts := readEvents(t, path)
	if len(evts) != 1 {
		t.Fatalf("expected 1 event")
	}
	line, err := json.Marshal(evts[0])
	if err != nil {
		t.Fatal(err)
	}

	ok, seq, hashMatch, hmacMatch := VerifyOne(line, key)
	if !ok {
		t.Fatalf("VerifyOne rejected valid event: ok=%v hash=%v hmac=%v", ok, hashMatch, hmacMatch)
	}
	if seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}
	if !hashMatch {
		t.Fatal("hash should match")
	}
	if !hmacMatch {
		t.Fatal("hmac should match")
	}
}

func TestVerifyOneHashTampered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 1)

	evts := readEvents(t, path)
	evts[0].Subject = map[string]any{"injected": "evil"}
	mutated, _ := json.Marshal(evts[0])

	ok, seq, hashMatch, hmacMatch := VerifyOne(mutated, key)
	if ok {
		t.Fatal("VerifyOne should reject tampered event")
	}
	if seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}
	if hashMatch {
		t.Fatal("hash should not match after tamper")
	}
	// HMAC may still appear to match because it was computed over the
	// original hash, which is still stored in the event struct — but
	// hash_match=false already makes ok=false.
	_ = hmacMatch
}

func TestVerifyOneHMACTampered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := newTestKey(t)
	writeWithChain(t, path, key, 1)

	evts := readEvents(t, path)
	evts[0].HMAC = "deadbeef"
	mutated, _ := json.Marshal(evts[0])

	ok, seq, hashMatch, hmacMatch := VerifyOne(mutated, key)
	if ok {
		t.Fatal("VerifyOne should reject HMAC-tampered event")
	}
	if seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}
	if !hashMatch {
		t.Fatal("hash should still match when only HMAC is tampered")
	}
	if hmacMatch {
		t.Fatal("hmac should not match after tamper")
	}
}

func TestVerifyOneLegacyEvent(t *testing.T) {
	legacy := []byte(`{"schema_version":"v0.1","timestamp":"2026-01-01T00:00:00Z","event_id":"old-1","host":"test","category":"process","severity":"low","action":"observe","decision":"alert"}`)
	ok, seq, hashMatch, hmacMatch := VerifyOne(legacy, nil)
	if !ok {
		t.Fatal("VerifyOne should pass legacy events")
	}
	if seq != 0 {
		t.Fatalf("seq = %d, want 0", seq)
	}
	if !hashMatch || !hmacMatch {
		t.Fatal("legacy events should trivially match")
	}
}

func TestVerifyOneEmptyLine(t *testing.T) {
	ok, _, hashMatch, hmacMatch := VerifyOne(nil, nil)
	if !ok || !hashMatch || !hmacMatch {
		t.Fatal("empty line should pass")
	}
	ok, _, hashMatch, hmacMatch = VerifyOne([]byte{}, nil)
	if !ok || !hashMatch || !hmacMatch {
		t.Fatal("empty line should pass")
	}
}

func TestVerifyOneMalformedJSON(t *testing.T) {
	ok, _, hashMatch, hmacMatch := VerifyOne([]byte("not json"), nil)
	if ok || hashMatch || hmacMatch {
		t.Fatal("malformed JSON should fail")
	}
}

// Sanity: ensure the import path strings used in errors match.
var _ = strings.Contains
