package ocikms

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// stubHandler records what the loop handed it and answers from a script.
type stubHandler struct {
	gotConfig    map[string]any
	gotPlaintext []byte
	gotWrapped   string

	wrapped string
	keyRef  string
	encErr  error

	plaintext []byte
	decErr    error
}

func (s *stubHandler) Encrypt(config map[string]any, plaintext []byte) (string, string, error) {
	s.gotConfig = config
	s.gotPlaintext = plaintext
	return s.wrapped, s.keyRef, s.encErr
}

func (s *stubHandler) Decrypt(wrapped string) ([]byte, error) {
	s.gotWrapped = wrapped
	return s.plaintext, s.decErr
}

// session drives Serve over in-memory pipes and reads responses line by line.
type session struct {
	t    *testing.T
	inW  io.Writer
	dec  *json.Decoder
	done chan error
}

func newSession(t *testing.T, h Handler) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &session{t: t, inW: inW, dec: json.NewDecoder(outR), done: make(chan error, 1)}
	go func() { s.done <- Serve(inR, outW, h, "9.9.9-test") }()
	return s
}

func (s *session) send(line string) {
	s.t.Helper()
	s.write(line + "\n")
}

// write sends a raw frame; used where the terminator is deliberately not a
// bare LF (CRLF tolerance).
func (s *session) write(frame string) {
	s.t.Helper()
	if _, err := s.inW.Write([]byte(frame)); err != nil {
		s.t.Fatalf("send: %v", err)
	}
}

// read decodes the next response from the session's shared decoder.
func (s *session) read() map[string]any {
	s.t.Helper()
	var v map[string]any
	if err := s.dec.Decode(&v); err != nil {
		s.t.Fatalf("reading response: %v", err)
	}
	return v
}

func (s *session) close() error {
	s.inW.(io.Closer).Close()
	return <-s.done
}

func TestHandshakeReply(t *testing.T) {
	s := newSession(t, &stubHandler{})
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	got := s.read()
	if got["protocol"] != "sops-plugin" {
		t.Fatalf("protocol = %v", got["protocol"])
	}
	if got["version"] != float64(1) {
		t.Fatalf("version = %v", got["version"])
	}
	if got["plugin"] != "ocikms" {
		t.Fatalf("plugin = %v", got["plugin"])
	}
	if got["plugin_version"] != "9.9.9-test" {
		t.Fatalf("plugin_version = %v", got["plugin_version"])
	}
}

func TestHandshakeRejectsWrongProtocol(t *testing.T) {
	err := Serve(
		strings.NewReader("{\"protocol\":\"other\",\"max_version\":1}\n"),
		io.Discard, &stubHandler{}, "0.1.0")
	if err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("want protocol error, got %v", err)
	}
}

func TestEncryptDecryptExchange(t *testing.T) {
	h := &stubHandler{wrapped: "ocikms.v1.QUJD", keyRef: "key-1", plaintext: []byte("recovered")}
	s := newSession(t, h)
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	s.read()

	s.send(`{"id":7,"action":"encrypt","config":{"key_id":"k"},"plaintext":"c2VjcmV0"}`)
	resp := s.read()
	if resp["id"] != float64(7) || resp["ok"] != true {
		t.Fatalf("encrypt response: %v", resp)
	}
	if resp["wrapped"] != "ocikms.v1.QUJD" || resp["key_ref"] != "key-1" {
		t.Fatalf("encrypt response fields: %v", resp)
	}
	if h.gotConfig["key_id"] != "k" {
		t.Fatalf("config not forwarded: %v", h.gotConfig)
	}
	if string(h.gotPlaintext) != "secret" {
		t.Fatalf("plaintext not base64-decoded: %q", h.gotPlaintext)
	}

	s.send(`{"id":8,"action":"decrypt","wrapped":"ocikms.v1.QUJD"}`)
	resp = s.read()
	if resp["id"] != float64(8) || resp["ok"] != true {
		t.Fatalf("decrypt response: %v", resp)
	}
	// plaintext is []byte on the wire: base64 of "recovered"
	if resp["plaintext"] != base64Of("recovered") {
		t.Fatalf("plaintext = %v", resp["plaintext"])
	}
	if h.gotWrapped != "ocikms.v1.QUJD" {
		t.Fatalf("wrapped not forwarded: %q", h.gotWrapped)
	}
}

func TestUnsupportedActionIsAnswered(t *testing.T) {
	s := newSession(t, &stubHandler{})
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	s.read()
	s.send(`{"id":3,"action":"sign","config":{}}`)
	resp := s.read()
	if resp["ok"] != false {
		t.Fatalf("expected ok:false, got %v", resp)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != CodeUnsupportedAction {
		t.Fatalf("code = %v", errObj["code"])
	}
	if errObj["message"] == "" {
		t.Fatal("error message must be non-empty")
	}
}

func TestGarbageRequestIsAnsweredNotFatal(t *testing.T) {
	s := newSession(t, &stubHandler{})
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	s.read()
	s.send(`this is not json`)
	resp := s.read()
	if resp["ok"] != false {
		t.Fatalf("expected ok:false, got %v", resp)
	}
	if resp["error"].(map[string]any)["code"] != CodeInvalidRequest {
		t.Fatalf("code = %v", resp["error"])
	}
	// the loop must survive and answer the next well-formed request
	s.send(`{"id":2,"action":"decrypt","wrapped":"x"}`)
	if resp := s.read(); resp["id"] != float64(2) {
		t.Fatalf("post-garbage response: %v", resp)
	}
}

func TestHandlerWireErrorSurfaces(t *testing.T) {
	h := &stubHandler{encErr: &WireError{Code: CodeConfigError, Message: "missing key_id"}}
	s := newSession(t, h)
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	s.read()
	s.send(`{"id":1,"action":"encrypt","config":{},"plaintext":"QUJD"}`)
	resp := s.read()
	errObj := resp["error"].(map[string]any)
	if errObj["code"] != CodeConfigError || errObj["message"] != "missing key_id" {
		t.Fatalf("error object: %v", errObj)
	}
}

func TestPlainHandlerErrorBecomesInternal(t *testing.T) {
	h := &stubHandler{decErr: errors.New("boom")}
	s := newSession(t, h)
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	s.read()
	s.send(`{"id":1,"action":"decrypt","wrapped":"ocikms.v1.eHg"}`)
	resp := s.read()
	if resp["error"].(map[string]any)["code"] != CodeInternal {
		t.Fatalf("code = %v", resp["error"])
	}
}

func TestEmptyWrappedFromHandlerRejected(t *testing.T) {
	h := &stubHandler{wrapped: "", keyRef: "k"}
	s := newSession(t, h)
	defer s.close()
	s.send(`{"protocol":"sops-plugin","max_version":1}`)
	s.read()
	s.send(`{"id":1,"action":"encrypt","config":{},"plaintext":"QUJD"}`)
	resp := s.read()
	if resp["ok"] != false || resp["error"].(map[string]any)["code"] != CodeInternal {
		t.Fatalf("response: %v", resp)
	}
}

func TestEOFExitsClean(t *testing.T) {
	err := Serve(
		strings.NewReader("{\"protocol\":\"sops-plugin\",\"max_version\":1}\n{\"id\":1,\"action\":\"encrypt\",\"config\":{},\"plaintext\":\"QUJD\"}\n"),
		io.Discard, &stubHandler{wrapped: "w"}, "0.1.0")
	if err != nil {
		t.Fatalf("clean EOF must exit nil, got %v", err)
	}
}

func TestOversizeLineRejected(t *testing.T) {
	huge := "{\"protocol\":\"sops-plugin\",\"max_version\":1}\n" + `{"id":1,"action":"decrypt","wrapped":"` + strings.Repeat("A", maxLineSize) + `"}`
	err := Serve(strings.NewReader(huge), io.Discard, &stubHandler{}, "0.1.0")
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("want oversize rejection, got %v", err)
	}
}

func TestResponsesAreLFOnlyAndCompleteLines(t *testing.T) {
	var buf bytes.Buffer
	in := strings.NewReader("{\"protocol\":\"sops-plugin\",\"max_version\":1}\n{\"id\":1,\"action\":\"encrypt\",\"config\":{},\"plaintext\":\"QUJD\"}\n")
	if err := Serve(in, &buf, &stubHandler{wrapped: "ocikms.v1.w", keyRef: "k"}, "0.1.0"); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if bytes.ContainsRune(out, '\r') {
		t.Fatal("CR byte in output; CRLF is forbidden")
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 response lines, got %d", len(lines))
	}
	if !bytes.HasSuffix(out, []byte("}\n")) {
		t.Fatal("output must end with a complete LF-terminated line")
	}
}

func base64Of(s string) string {
	b, _ := json.Marshal([]byte(s))
	var out string
	json.Unmarshal(b, &out)
	return out
}

func TestHandshakeRejectsOldMaxVersion(t *testing.T) {
	err := Serve(
		strings.NewReader("{\"protocol\":\"sops-plugin\",\"max_version\":0}\n"),
		io.Discard, &stubHandler{}, "0.1.0")
	if err == nil || !strings.Contains(err.Error(), "max_version") {
		t.Fatalf("want max_version rejection, got %v", err)
	}
}

// failWriter accepts n writes, then errors: simulates stdout dying mid-session.
type failWriter struct {
	n       int
	written int
}

func (w *failWriter) Write(p []byte) (int, error) {
	w.written++
	if w.written > w.n {
		return 0, errors.New("stdout broken")
	}
	return len(p), nil
}

func TestWriteFailureEndsServe(t *testing.T) {
	input := "{\"protocol\":\"sops-plugin\",\"max_version\":1}\n" +
		"{\"id\":1,\"action\":\"encrypt\",\"config\":{},\"plaintext\":\"QUJD\"}\n"
	cases := []struct {
		name      string
		after     int
		wantInErr string
	}{
		{"handshake write fails", 0, "handshake response"},
		{"first response write fails", 1, "writing response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Serve(strings.NewReader(input), &failWriter{n: tc.after},
				&stubHandler{wrapped: "w"}, "0.1.0")
			if err == nil || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("want %q error, got %v", tc.wantInErr, err)
			}
		})
	}
}

func TestExactBoundaryLineAccepted(t *testing.T) {
	// a line of exactly maxLineSize bytes INCLUDING the LF is the legal cap
	prefix := `{"id":1,"action":"decrypt","wrapped":"`
	suffix := `"}`
	filler := maxLineSize - 1 - len(prefix) - len(suffix)
	line := prefix + strings.Repeat("A", filler) + suffix
	if len(line) != maxLineSize-1 {
		t.Fatalf("line is %d bytes, want %d", len(line), maxLineSize-1)
	}
	input := "{\"protocol\":\"sops-plugin\",\"max_version\":1}\n" + line + "\n"
	var buf bytes.Buffer
	err := Serve(strings.NewReader(input), &buf, &stubHandler{plaintext: []byte("x")}, "0.1.0")
	if err != nil {
		t.Fatalf("boundary line must be accepted, got %v", err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Fatalf("want 2 response lines, got %d", n)
	}
}

// TestOneByteOverBoundaryRejected: a line of maxLineSize content bytes plus
// the LF (maxLineSize+1 total) is one byte past the host's cap and must
// reject, matching the host semantics instead of accepting a byte more.
func TestOneByteOverBoundaryRejected(t *testing.T) {
	prefix := `{"id":1,"action":"decrypt","wrapped":"`
	suffix := `"}`
	filler := maxLineSize - len(prefix) - len(suffix)
	line := prefix + strings.Repeat("A", filler) + suffix
	if len(line) != maxLineSize {
		t.Fatalf("line is %d bytes, want %d", len(line), maxLineSize)
	}
	input := "{\"protocol\":\"sops-plugin\",\"max_version\":1}\n" + line + "\n"
	err := Serve(strings.NewReader(input), io.Discard, &stubHandler{}, "0.1.0")
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("want oversize rejection, got %v", err)
	}
}

func TestInboundCRLFTolerated(t *testing.T) {
	// the host never sends CRLF, but a trailing CR is JSON whitespace; the
	// reader is lenient and the exchange still works
	h := &stubHandler{wrapped: "ocikms.v1.QUJD", plaintext: []byte("recovered")}
	s := newSession(t, h)
	defer s.close()
	s.write("{\"protocol\":\"sops-plugin\",\"max_version\":1}\r\n")
	s.read()
	s.write("{\"id\":4,\"action\":\"encrypt\",\"config\":{\"key_id\":\"k\"},\"plaintext\":\"c2VjcmV0\"}\r\n")
	resp := s.read()
	if resp["id"] != float64(4) || resp["ok"] != true || resp["wrapped"] != "ocikms.v1.QUJD" {
		t.Fatalf("CRLF-terminated request was not answered: %v", resp)
	}
}
