package ocisim

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The suite drives the real plugin binary (fake mode OFF) over sops-plugin/1
// against the simulator, so every request is a real SDK-signed HTTP call.

var (
	sim        *Server
	pluginBin  string
	credEnv    []string
	credKeyDir string
)

func TestMain(m *testing.M) {
	var err error
	sim, err = Start()
	if err != nil {
		// not a failure: machines without stunt skip the suite
		fmt.Fprintf(os.Stderr, "ocisim: skipping suite, no stunt server: %v\n", err)
		sim = nil
	}
	dir, err := os.MkdirTemp("", "ocisim-creds-*")
	if err != nil {
		if sim != nil {
			sim.Close()
		}
		fmt.Fprintln(os.Stderr, "ocisim:", err)
		os.Exit(1)
	}
	credKeyDir = dir
	if code, err := buildPluginAndCreds(dir); err != nil {
		// no m.Run(): release everything before the exit code is lost
		if sim != nil {
			sim.Close()
		}
		os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "ocisim:", err)
		os.Exit(1)
	} else if code != 0 {
		if sim != nil {
			sim.Close()
		}
		os.RemoveAll(dir)
		os.Exit(code)
	}
	code := m.Run()
	if sim != nil {
		sim.Close()
	}
	os.RemoveAll(dir)
	os.Exit(code)
}

// buildPluginAndCreds compiles the plugin binary and writes the throwaway RSA
// key the SDK signs with. Returns a nonzero exit code only for a failed
// build; a missing stunt binary is a skip, not a failure.
func buildPluginAndCreds(dir string) (int, error) {
	pluginBin = filepath.Join(dir, "sops-plugin-ocikms"+exeSuffix())
	if out, err := exec.Command("go", "build", "-o", pluginBin, "github.com/deblasis/sops-plugin-ocikms/cmd/sops-plugin-ocikms").CombinedOutput(); err != nil {
		return 1, fmt.Errorf("building plugin: %v: %s", err, out)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 1, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		return 1, err
	}
	// the signature is never verified by the simulator; the values just have
	// to make the SDK's env credential provider happy
	credEnv = append(os.Environ(),
		"OCI_CLI_TENANCY=ocid1.tenancy.oc1..sim",
		"OCI_CLI_USER=ocid1.user.oc1..sim",
		"OCI_CLI_REGION=sim-region",
		"OCI_CLI_FINGERPRINT=aa:bb:cc:dd",
		"OCI_CLI_KEY_FILE="+keyPath,
		// keep the default config file provider out of the picture
		"HOME="+dir,
		"USERPROFILE="+dir,
	)
	return 0, nil
}

type pluginSession struct {
	t   *testing.T
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startPlugin(t *testing.T) *pluginSession {
	t.Helper()
	requireSim(t)
	cmd := exec.Command(pluginBin)
	cmd.Env = credEnv
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// registered before the handshake: a failed handshake must not leak the
	// process just because cleanup was not reached yet
	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
	})
	s := &pluginSession{t: t, cmd: cmd, in: stdin, out: bufio.NewReaderSize(stdout, 16<<20)}
	s.handshake()
	return s
}

type wireResponse struct {
	ID        int64  `json:"id"`
	OK        bool   `json:"ok"`
	Plaintext []byte `json:"plaintext"`
	Wrapped   string `json:"wrapped"`
	KeyRef    string `json:"key_ref"`
	Error     *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (s *pluginSession) handshake() {
	s.t.Helper()
	fmt.Fprintln(s.in, `{"protocol":"sops-plugin","max_version":1}`)
	var hs struct {
		Protocol string `json:"protocol"`
		Plugin   string `json:"plugin"`
	}
	line, err := s.out.ReadString('\n')
	if err != nil {
		s.t.Fatalf("handshake read: %v", err)
	}
	if err := json.Unmarshal([]byte(line), &hs); err != nil {
		s.t.Fatalf("handshake line %q: %v", line, err)
	}
	if hs.Protocol != "sops-plugin" || hs.Plugin != "ocikms" {
		s.t.Fatalf("handshake: %+v", hs)
	}
}

func (s *pluginSession) do(req any) wireResponse {
	s.t.Helper()
	payload, err := json.Marshal(req)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.in.Write(append(payload, '\n')); err != nil {
		s.t.Fatalf("write %s: %v", payload, err)
	}
	line, err := s.out.ReadString('\n')
	if err != nil {
		s.t.Fatalf("read after %s: %v", payload, err)
	}
	var res wireResponse
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		s.t.Fatalf("response line %q: %v", line, err)
	}
	return res
}

func encryptReq(id int64, keyID, endpoint string, plaintext []byte) any {
	return struct {
		ID        int64          `json:"id"`
		Action    string         `json:"action"`
		Config    map[string]any `json:"config"`
		Plaintext []byte         `json:"plaintext"`
	}{id, "encrypt", map[string]any{"key_id": keyID, "crypto_endpoint": endpoint}, plaintext}
}

func decryptReq(id int64, wrapped string) any {
	return struct {
		ID      int64  `json:"id"`
		Action  string `json:"action"`
		Wrapped string `json:"wrapped"`
	}{id, "decrypt", wrapped}
}

// requireSim keeps the clean-skip behavior: without stunt the whole suite
// skips, including tests that flip profiles before starting a plugin.
func requireSim(t *testing.T) {
	t.Helper()
	if sim == nil {
		t.Skip("stunt server unavailable")
	}
}

// cleanupDeactivate restores healthy behavior after the test; a failed
// deactivate would poison every later test on the shared server, so it is an
// error, not a log line.
func cleanupDeactivate(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if err := sim.Deactivate(); err != nil {
			t.Errorf("deactivate after test: %v", err)
		}
	})
}

func wantCode(t *testing.T, res wireResponse, code string) {
	t.Helper()
	if res.OK {
		t.Fatalf("expected failure %s, got ok: %+v", code, res)
	}
	if res.Error == nil || res.Error.Code != code {
		t.Fatalf("expected code %s, got %+v", code, res.Error)
	}
}

func TestRoundTripE2E(t *testing.T) {
	s := startPlugin(t)
	probe := []byte("exactly-32-byte-data-key-12345")
	for _, key := range []string{Key1, Key2} {
		res := s.do(encryptReq(1, key, sim.Endpoint(), probe))
		if !res.OK {
			t.Fatalf("encrypt with %s: %+v", key, res.Error)
		}
		if res.KeyRef != key {
			t.Fatalf("key_ref = %q, want %q", res.KeyRef, key)
		}
		if !strings.HasPrefix(res.Wrapped, "ocikms.v1.") {
			t.Fatalf("wrapped %q lacks the blob prefix", res.Wrapped)
		}
		back := s.do(decryptReq(2, res.Wrapped))
		if !back.OK {
			t.Fatalf("decrypt: %+v", back.Error)
		}
		if string(back.Plaintext) != string(probe) {
			t.Fatalf("round trip mismatch: %q != %q", back.Plaintext, probe)
		}
	}
}

func TestUnknownKeyIsKeyUnavailable(t *testing.T) {
	s := startPlugin(t)
	res := s.do(encryptReq(1, "ocid1.key.oc1.sim-region.simvault.nosuchkey", sim.Endpoint(), []byte("k")))
	wantCode(t, res, "key_unavailable")
}

// TestResetInvalidatesOldCiphertexts: reset mints a new ciphertext-name
// generation, so a pre-reset blob must not decrypt afterwards while a fresh
// round trip still works.
func TestResetInvalidatesOldCiphertexts(t *testing.T) {
	requireSim(t)
	s := startPlugin(t)
	res := s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("before-reset")))
	if !res.OK {
		t.Fatalf("encrypt: %+v", res.Error)
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.do(decryptReq(2, res.Wrapped)), "key_unavailable")
	fresh := s.do(encryptReq(3, Key1, sim.Endpoint(), []byte("after-reset")))
	if !fresh.OK {
		t.Fatalf("fresh encrypt after reset: %+v", fresh.Error)
	}
	if fresh.Wrapped == res.Wrapped {
		t.Fatalf("seq rewound into the old ciphertext name: %q", fresh.Wrapped)
	}
	back := s.do(decryptReq(4, fresh.Wrapped))
	if !back.OK || string(back.Plaintext) != "after-reset" {
		t.Fatalf("fresh round trip after reset: ok=%v %+v", back.OK, back.Error)
	}
}

// TestDecryptBindsCiphertextToKey: the simulator binds each ciphertext to its
// key, so a blob whose keyId was swapped after encrypt must not decrypt.
func TestDecryptBindsCiphertextToKey(t *testing.T) {
	s := startPlugin(t)
	res := s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	if !res.OK {
		t.Fatalf("encrypt: %+v", res.Error)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(res.Wrapped, "ocikms.v1."))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		KeyID          string `json:"keyId"`
		CryptoEndpoint string `json:"cryptoEndpoint"`
		Region         string `json:"region"`
		CiphertextB64  string `json:"ciphertext"`
	}
	if err := json.Unmarshal(payload, &b); err != nil {
		t.Fatal(err)
	}
	b.KeyID = Key2
	forged, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.do(decryptReq(2, "ocikms.v1."+base64.StdEncoding.EncodeToString(forged))), "invalid_request")
}

func TestFailureInjectionProfiles(t *testing.T) {
	cases := []struct {
		profile string
		want    string
	}{
		{"auth-401", "auth_failed"},
		{"auth-403", "auth_failed"},
		{"key-gone-404", "key_unavailable"},
		{"throttled-429", "key_unavailable"},
		{"outage-500", "key_unavailable"},
		{"unavailable-503", "key_unavailable"},
		// a 200 the SDK cannot parse is not a service error: internal
		{"garbage", "internal"},
	}
	for _, tc := range cases {
		t.Run(tc.profile, func(t *testing.T) {
			requireSim(t)
			if err := sim.Activate(tc.profile); err != nil {
				t.Fatal(err)
			}
			cleanupDeactivate(t)
			s := startPlugin(t)
			res := s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
			wantCode(t, res, tc.want)
		})
	}
}

func TestProfileRecovery(t *testing.T) {
	requireSim(t)
	if err := sim.Activate("outage-500"); err != nil {
		t.Fatal(err)
	}
	s := startPlugin(t)
	wantCode(t, s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k"))), "key_unavailable")
	if err := sim.Deactivate(); err != nil {
		t.Fatal(err)
	}
	res := s.do(encryptReq(2, Key1, sim.Endpoint(), []byte("k")))
	if !res.OK {
		t.Fatalf("healthy after deactivate: %+v", res.Error)
	}
}

func TestFlapAlternates(t *testing.T) {
	requireSim(t)
	// flap parity is a KV counter: reset so the first call fails regardless
	// of what earlier tests did to it
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := sim.Activate("flap"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	wantCode(t, s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k"))), "key_unavailable")
	res := s.do(encryptReq(2, Key1, sim.Endpoint(), []byte("k")))
	if !res.OK {
		t.Fatalf("second flap call must succeed: %+v", res.Error)
	}
}

func TestOversizedCiphertext(t *testing.T) {
	requireSim(t)
	if err := sim.Activate("oversized"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	res := s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	if !res.OK {
		t.Fatalf("oversized encrypt must still answer ok: %+v", res.Error)
	}
	// 1.1MB ciphertext, base64 again inside the blob: well past the host's
	// 1 MiB protocol cap, so downstream consumers choke, not the plugin
	if len(res.Wrapped) <= 1<<20 {
		t.Fatalf("wrapped blob too small to be oversized: %d", len(res.Wrapped))
	}
}

func TestSlowFailureIsKeyUnavailable(t *testing.T) {
	requireSim(t)
	if err := sim.Activate("slow-500-3s"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	start := time.Now()
	res := s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	wantCode(t, res, "key_unavailable")
	if elapsed := time.Since(start); elapsed < 2500*time.Millisecond {
		t.Fatalf("failure arrived too early (%v): latency not injected", elapsed)
	}
}

// TestHangHitsPluginDeadline is the timeout boundary: the connection drops at
// 45s but the plugin's own 30s deadline must fire first. 30s wall clock, so
// it only runs when OCISIM_SLOW=1.
func TestHangHitsPluginDeadline(t *testing.T) {
	if os.Getenv("OCISIM_SLOW") != "1" {
		t.Skip("set OCISIM_SLOW=1 for the 30s hang boundary test")
	}
	requireSim(t)
	if err := sim.Activate("hang"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	start := time.Now()
	res := s.do(encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	wantCode(t, res, "key_unavailable")
	if elapsed := time.Since(start); elapsed < 25*time.Second || elapsed > 40*time.Second {
		t.Fatalf("deadline at %v, want ~30s", elapsed)
	}
}
