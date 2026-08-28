package ocisim

// The adversarial battery (P17): each scenario drives the real plugin binary
// (fake mode OFF) against the simulator and asserts BOTH the mapped frozen
// error code AND the sops-side semantics: no hang beyond the plugin's own
// deadline, clean process exit, exactly one response per operation.
//
// Scenario 6's hang half (30s deadline vs 45s drop) is TestHangHitsPluginDeadline
// in ocisim_test.go behind OCISIM_SLOW=1; it is not duplicated here.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// op sends one request and asserts the id echo, which is the lockstep proof
// that the plugin answered exactly one response for this operation.
func op(s *pluginSession, id int64, req any) wireResponse {
	s.t.Helper()
	res := s.do(req)
	if res.ID != id {
		s.t.Fatalf("response id %d, want %d (stale or extra response in stream)", res.ID, id)
	}
	return res
}

// stopSession closes stdin and asserts the plugin process exits on its own
// within the budget; a plugin that only dies on Kill is a leak. Returns the
// exit code. The t.Cleanup Wait in startPlugin becomes a no-op second Wait.
func stopSession(t *testing.T, s *pluginSession) int {
	t.Helper()
	s.in.Close()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("plugin wait: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("plugin process did not exit after stdin close")
	}
	return -1
}

// Scenario 1: credential rejection under valid-looking creds is auth_failed
// (fatal, never retried), and deactivating restores service.
func TestBatteryAuthRejectionRoundTrip(t *testing.T) {
	requireSim(t)
	for _, profile := range []string{"auth-401", "auth-403"} {
		t.Run(profile, func(t *testing.T) {
			if err := sim.Activate(profile); err != nil {
				t.Fatal(err)
			}
			cleanupDeactivate(t)
			s := startPlugin(t)
			wantCode(t, op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k"))), "auth_failed")
			if err := sim.Deactivate(); err != nil {
				t.Fatal(err)
			}
			res := op(s, 2, encryptReq(2, Key1, sim.Endpoint(), []byte("k")))
			if !res.OK {
				t.Fatalf("no recovery after deactivate: %+v", res.Error)
			}
			back := op(s, 3, decryptReq(3, res.Wrapped))
			if !back.OK || string(back.Plaintext) != "k" {
				t.Fatalf("recovery round trip: ok=%v %+v", back.OK, back.Error)
			}
		})
	}
}

// throttleCount extracts the request counter the adapter embeds in the 429
// message; the battery uses it to prove one HTTP request per operation.
func throttleCount(t *testing.T, res wireResponse) int {
	t.Helper()
	const marker = "(request "
	i := strings.LastIndex(res.Error.Message, marker)
	if i < 0 {
		t.Fatalf("429 message carries no request counter: %q", res.Error.Message)
	}
	rest := res.Error.Message[i+len(marker):]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		t.Fatalf("429 message counter unterminated: %q", res.Error.Message)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		t.Fatalf("429 message counter not numeric: %q", res.Error.Message)
	}
	return n
}

// Scenario 2: sustained throttling. Five sequential operations, every one
// key_unavailable, and the adapter-side counter advances by exactly one per
// operation, so neither the plugin nor the SDK retried. The Retry-After
// header case is the manifest throttled-429 profile (asserted first).
func TestBatterySustainedThrottleNoRetryStorm(t *testing.T) {
	requireSim(t)
	t.Run("429 with Retry-After", func(t *testing.T) {
		if err := sim.Activate("throttled-429"); err != nil {
			t.Fatal(err)
		}
		cleanupDeactivate(t)
		s := startPlugin(t)
		wantCode(t, op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k"))), "key_unavailable")
	})
	t.Run("five sequential ops, one request each", func(t *testing.T) {
		if err := sim.Reset(); err != nil {
			t.Fatal(err)
		}
		if err := sim.Activate("throttle-99"); err != nil {
			t.Fatal(err)
		}
		cleanupDeactivate(t)
		s := startPlugin(t)
		want := 0
		for i := 1; i <= 5; i++ {
			start := time.Now()
			res := op(s, int64(i), encryptReq(int64(i), Key1, sim.Endpoint(), []byte("k")))
			wantCode(t, res, "key_unavailable")
			got := throttleCount(t, res)
			if got != want+1 {
				t.Fatalf("operation %d saw server request %d, want %d: the plugin or SDK retried", i, got, want+1)
			}
			want = got
			// an unanswered Retry-After sleep or a retry loop would show here
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("operation %d took %v: retry/backoff suspected", i, elapsed)
			}
		}
		if err := sim.Deactivate(); err != nil {
			t.Fatal(err)
		}
		if res := op(s, 6, encryptReq(6, Key1, sim.Endpoint(), []byte("k"))); !res.OK {
			t.Fatalf("healthy after sustained throttle: %+v", res.Error)
		}
	})
}

// Scenario 3: ten flap cycles. The KV counter makes the alternation
// deterministic: every odd handler call fails key_unavailable, every even one
// round-trips, and the blob written before a failure decrypts cleanly once
// the flap is deactivated (no cross-request state corruption).
func TestBatteryFlapCycles(t *testing.T) {
	requireSim(t)
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := sim.Activate("flap"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	var id int64
	next := func() int64 { id++; return id }
	for i := 0; i < 5; i++ {
		probe := []byte(fmt.Sprintf("c%d", i))
		// id pinned per call: no reliance on Go's left-to-right argument
		// evaluation to keep request id and expectation in sync
		id = next()
		wantCode(t, op(s, id, encryptReq(id, Key1, sim.Endpoint(), probe)), "key_unavailable")
		id = next()
		ok := op(s, id, encryptReq(id, Key1, sim.Endpoint(), probe))
		if !ok.OK {
			t.Fatalf("cycle %d: even call must succeed: %+v", i, ok.Error)
		}
		id = next()
		wantCode(t, op(s, id, decryptReq(id, ok.Wrapped)), "key_unavailable")
		id = next()
		back := op(s, id, decryptReq(id, ok.Wrapped))
		if !back.OK || string(back.Plaintext) != fmt.Sprintf("c%d", i) {
			t.Fatalf("cycle %d: round trip: ok=%v %+v", i, back.OK, back.Error)
		}
	}
	if err := sim.Deactivate(); err != nil {
		t.Fatal(err)
	}
}

// Count-bounded adapter contract (Part A): throttle-N fails exactly N times
// then recovers, and Reset re-arms the counter.
func TestBatteryThrottleNCountSemantics(t *testing.T) {
	requireSim(t)
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := sim.Activate("throttle-3"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	for i := 1; i <= 3; i++ {
		res := op(s, int64(i), encryptReq(int64(i), Key1, sim.Endpoint(), []byte("k")))
		wantCode(t, res, "key_unavailable")
		if got := throttleCount(t, res); got != i {
			t.Fatalf("429 number %d, want %d", got, i)
		}
	}
	res := op(s, 4, encryptReq(4, Key1, sim.Endpoint(), []byte("k")))
	if !res.OK {
		t.Fatalf("4th call must be healthy: %+v", res.Error)
	}
	// re-arming the same bound requires Reset: the counter persists
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := sim.Activate("throttle-3"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, op(s, 5, encryptReq(5, Key1, sim.Endpoint(), []byte("k"))), "key_unavailable")
	if got := throttleCount(t, op(s, 6, encryptReq(6, Key1, sim.Endpoint(), []byte("k")))); got != 2 {
		t.Fatalf("after re-arm the counter restarted at 2, got %d", got)
	}
}

// Count-bounded adapter contract (Part A): burst-garbage-N answers a non-JSON
// 200 exactly N times (classify: internal, a 200 the SDK cannot parse), then
// recovers.
func TestBatteryBurstGarbageCountSemantics(t *testing.T) {
	requireSim(t)
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := sim.Activate("burst-garbage-2"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	wantCode(t, op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k"))), "internal")
	wantCode(t, op(s, 2, encryptReq(2, Key1, sim.Endpoint(), []byte("k"))), "internal")
	res := op(s, 3, encryptReq(3, Key1, sim.Endpoint(), []byte("k")))
	if !res.OK {
		t.Fatalf("3rd call must be healthy: %+v", res.Error)
	}
	if back := op(s, 4, decryptReq(4, res.Wrapped)); !back.OK || string(back.Plaintext) != "k" {
		t.Fatalf("healthy round trip after burst: ok=%v %+v", back.OK, back.Error)
	}
}

// Scenario 5: malformed success bodies. A garbage 200 is internal (existing
// coverage). An oversized ciphertext trips the plugin's outbound cap (128 KiB,
// symmetric with the empty-ciphertext guard): the answer is internal, so a
// megabyte blob never reaches the wire. The inbound 1MiB line cap remains the
// last line of defense for oversized blobs arriving from outside: a
// hand-forged >1MiB wrapped value fed to decrypt gets no response line and a
// non-zero exit, never a hang.
func TestBatteryOversizedCiphertextCapped(t *testing.T) {
	requireSim(t)
	if err := sim.Activate("oversized"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	res := op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	if res.OK || res.Error == nil || res.Error.Code != "internal" {
		t.Fatalf("want internal from the outbound cap, got ok=%v %+v", res.OK, res.Error)
	}

	// inbound half: forge the >1MiB blob the plugin would have refused to emit
	blobJSON, _ := json.Marshal(struct {
		KeyID          string `json:"keyId"`
		CryptoEndpoint string `json:"cryptoEndpoint"`
		Region         string `json:"region"`
		CiphertextB64  string `json:"ciphertext"`
	}{Key1, sim.Endpoint(), "sim-region", strings.Repeat("A", 1200000)})
	forged := "ocikms.v1." + base64.StdEncoding.EncodeToString(blobJSON)
	payload, err := json.Marshal(decryptReq(2, forged))
	if err != nil {
		t.Fatal(err)
	}
	// the write may fail mid-line: the plugin hits the cap after buffering
	// 1MiB+1 and exits without draining the rest, so a broken pipe here is
	// expected, not an error; the request was still delivered far past the cap
	_, _ = s.in.Write(append(payload, '\n'))
	// the line cap kills the read loop: the plugin must exit rather than
	// answer; any read error (EOF or closed pipe) proves no response line
	line, err := s.out.ReadString('\n')
	if err == nil {
		t.Fatalf("oversized decrypt must not be answered, got %q", line)
	}
	if code := stopSession(t, s); code == 0 {
		t.Fatal("oversized decrypt must exit non-zero (stream unusable)")
	}
}

// Scenario 6 (fast half): a slow failure is still key_unavailable, on both
// encrypt and decrypt, and the latency proves the call was not short-circuited.
func TestBatterySlowFailuresBothPaths(t *testing.T) {
	requireSim(t)
	if err := sim.Activate("slow-500-3s"); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	start := time.Now()
	res := op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	wantCode(t, res, "key_unavailable")
	if elapsed := time.Since(start); elapsed < 2500*time.Millisecond {
		t.Fatalf("encrypt failure arrived too early (%v)", elapsed)
	}
	blobJSON, _ := json.Marshal(struct {
		KeyID          string `json:"keyId"`
		CryptoEndpoint string `json:"cryptoEndpoint"`
		Region         string `json:"region"`
		CiphertextB64  string `json:"ciphertext"`
	}{Key1, sim.Endpoint(), "sim-region", "ocisim-x-1"})
	wrapped := "ocikms.v1." + base64.StdEncoding.EncodeToString(blobJSON)
	start = time.Now()
	wantCode(t, op(s, 2, decryptReq(2, wrapped)), "key_unavailable")
	if elapsed := time.Since(start); elapsed < 2500*time.Millisecond {
		t.Fatalf("decrypt failure arrived too early (%v)", elapsed)
	}
}

// Scenario 7: no credentials anywhere (env scrubbed, HOME/USERPROFILE in an
// empty dir) against a healthy simulator. The credential chain is forced at
// client construction, so this maps auth_failed, not a per-request mystery.
//
// Layering caveat the skip below encodes: the SDK's DefaultConfigProvider
// resolves home via os/user (user.Current().HomeDir), which on Windows comes
// from the OS profile and IGNORES HOME/USERPROFILE overrides. A developer box
// with a real ~/.oci/config therefore feeds the plugin live credentials
// regardless of the scrubbed env, and the scenario cannot isolate; only a
// machine without a real config file can prove the auth_failed mapping.
func TestBatteryNoCredentialsMapsAuthFailed(t *testing.T) {
	requireSim(t)
	if u, err := osuser.Current(); err == nil {
		for _, rel := range []string{".oci/config", ".obmcs/config"} {
			if _, err := os.Stat(filepath.Join(u.HomeDir, rel)); err == nil {
				t.Skipf("real %s under the os/user home (%s) defeats the scrubbed env", rel, u.HomeDir)
			}
		}
	}
	emptyHome := t.TempDir()
	var env []string
	for _, kv := range os.Environ() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if strings.HasPrefix(k, "OCI_") || k == "SOPS_OCIKMS_FAKE_KMS" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+emptyHome, "USERPROFILE="+emptyHome)

	s := startPluginWithEnv(t, env)
	start := time.Now()
	res := op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
	if elapsed := time.Since(start); elapsed > 60*time.Second {
		t.Fatalf("missing creds took %v: the credential chain stalled", elapsed)
	}
	if res.OK || res.Error == nil || res.Error.Code != "auth_failed" {
		t.Fatalf("want auth_failed, got %+v", res.Error)
	}
	t.Logf("missing-creds probe took %v (instance-principal fallback dominates)", time.Since(start))
}

// Scenario 8: a blob minted by simulator A does not decrypt when its routing
// is forged at simulator B (independent worlds: unknown ciphertext 404 ->
// key_unavailable), while a wrong-key blob on the SAME server is a client
// mistake (existing binding -> invalid_request).
func TestBatteryEndpointAndKeyMismatch(t *testing.T) {
	requireSim(t)
	s := startPlugin(t)
	minted := op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("mismatch-probe")))
	if !minted.OK {
		t.Fatalf("mint: %+v", minted.Error)
	}

	sim2, err := Start()
	if err != nil {
		t.Fatalf("second simulator: %v", err)
	}
	defer sim2.Close()

	mutate := func(f func(b *map[string]any)) string {
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(minted.Wrapped, "ocikms.v1."))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatal(err)
		}
		f(&m)
		forged, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return "ocikms.v1." + base64.StdEncoding.EncodeToString(forged)
	}

	// routed at simulator B: B's ciphertext-name generation differs, so its
	// 404 (not key-known/wrong-key 400) wins
	cross := mutate(func(m *map[string]any) { (*m)["cryptoEndpoint"] = sim2.Endpoint() })
	wantCode(t, op(s, 2, decryptReq(2, cross)), "key_unavailable")

	// same server, wrong key: the ciphertext IS known, only the key is wrong
	wrongKey := mutate(func(m *map[string]any) { (*m)["keyId"] = Key2 })
	wantCode(t, op(s, 3, decryptReq(3, wrongKey)), "invalid_request")

	// the untouched blob still decrypts: forgeries left no trace
	back := op(s, 4, decryptReq(4, minted.Wrapped))
	if !back.OK || string(back.Plaintext) != "mismatch-probe" {
		t.Fatalf("original blob corrupted by forgeries: ok=%v %+v", back.OK, back.Error)
	}
}

// Scenario 9: a healthy multi-request session with a flap firing
// mid-sequence. Answers stay correct per request: under the flap the odd
// decrypt fails key_unavailable and the even one round-trips exactly; after
// deactivation the earlier blob still decrypts (no cross-request corruption).
func TestBatterySessionResilientToMidSequenceFlap(t *testing.T) {
	requireSim(t)
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	cleanupDeactivate(t)
	s := startPlugin(t)
	e1 := op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("first")))
	if !e1.OK {
		t.Fatalf("encrypt 1: %+v", e1.Error)
	}
	e2 := op(s, 2, encryptReq(2, Key1, sim.Endpoint(), []byte("second")))
	if !e2.OK {
		t.Fatalf("encrypt 2: %+v", e2.Error)
	}
	// the flap fires mid-sequence: the next handler call is the odd one
	if err := sim.Activate("flap"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, op(s, 3, decryptReq(3, e2.Wrapped)), "key_unavailable")
	back2 := op(s, 4, decryptReq(4, e2.Wrapped))
	if !back2.OK || string(back2.Plaintext) != "second" {
		t.Fatalf("decrypt 2 after flap: ok=%v %+v", back2.OK, back2.Error)
	}
	if err := sim.Deactivate(); err != nil {
		t.Fatal(err)
	}
	back1 := op(s, 5, decryptReq(5, e1.Wrapped))
	if !back1.OK || string(back1.Plaintext) != "first" {
		t.Fatalf("pre-flap blob after recovery: ok=%v %+v", back1.OK, back1.Error)
	}
}

// Scenario 10: rapid profile switching across ten alternating operations, no
// stuck profile, and the plugin processes exit cleanly when released (no
// leaks; stopSession fails the test if one lingers).
func TestBatteryRapidProfileSwitching(t *testing.T) {
	requireSim(t)
	cleanupDeactivate(t)
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			if err := sim.Activate("outage-500"); err != nil {
				t.Fatal(err)
			}
		} else if err := sim.Deactivate(); err != nil {
			t.Fatal(err)
		}
		s := startPlugin(t)
		res := op(s, 1, encryptReq(1, Key1, sim.Endpoint(), []byte("k")))
		if i%2 == 0 {
			wantCode(t, res, "key_unavailable")
		} else if !res.OK {
			t.Fatalf("operation %d must be healthy: %+v", i, res.Error)
		}
		if code := stopSession(t, s); code != 0 {
			t.Fatalf("operation %d: plugin exit code %d, want 0", i, code)
		}
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
}
