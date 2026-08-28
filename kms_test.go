package ocikms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wireErr asserts err carries the frozen code and returns it for inspection.
func wireErr(t *testing.T, err error) *WireError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var we *WireError
	if !errors.As(err, &we) {
		t.Fatalf("expected *WireError, got %T: %v", err, err)
	}
	if we.Code == "" || we.Message == "" {
		t.Fatalf("error object must carry non-empty code and message: %+v", we)
	}
	return we
}

// conformance probes from the spec: a ramp and a full 0x00..0xFF span, so a
// wrap that mangles NUL or high bytes cannot pass.
func rampProbe() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func spanProbe() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i * 0xFF / 31)
	}
	return b
}

func TestBlobRoundTripFakeMode(t *testing.T) {
	h := &KMSHandler{Fake: true, WarnWriter: io.Discard}
	config := map[string]any{
		"key_id":          "ocid1.key.oc1.eu-frankfurt-1.vault1.key1",
		"crypto_endpoint": "https://vault1-crypto.kms.eu-frankfurt-1.oraclecloud.com",
	}
	for _, probe := range [][]byte{rampProbe(), spanProbe(), []byte("exactly-32-byte-data-key-12345")} {
		wrapped, keyRef, err := h.Encrypt(config, probe)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		// fake mode forces its own key, so a fake blob is always
		// distinguishable by key_ref
		if keyRef != fakeKeyID {
			t.Fatalf("key_ref = %q, want the forced fake key %q", keyRef, fakeKeyID)
		}
		if !strings.HasPrefix(wrapped, "ocikms.v1.") {
			t.Fatalf("wrapped blob %q lacks the version prefix", wrapped)
		}
		if wrapped == string(probe) {
			t.Fatal("wrapped blob equals the plaintext")
		}
		back, err := h.Decrypt(wrapped)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if string(back) != string(probe) {
			t.Fatalf("round trip mismatch: %q != %q", back, probe)
		}
	}
}

// TestBlobCarriesRoutingFields runs on a non-fake handler with a scripted
// client so the config's real key id and endpoint ride inside the blob.
func TestBlobCarriesRoutingFields(t *testing.T) {
	h := handlerWithClient(fakeKMS{}, nil)
	wrapped, _, err := h.Encrypt(map[string]any{
		"key_id":          "ocid1.key.oc1.uk-london-1.vaultx.keyx",
		"crypto_endpoint": "https://vaultx-crypto.kms.uk-london-1.oraclecloud.com",
	}, rampProbe())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, BlobPrefix))
	if err != nil {
		t.Fatal(err)
	}
	var b blob
	if err := json.Unmarshal(payload, &b); err != nil {
		t.Fatal(err)
	}
	// decrypt must work from the blob alone: key id, endpoint and region all ride inside
	if b.KeyID != "ocid1.key.oc1.uk-london-1.vaultx.keyx" ||
		b.CryptoEndpoint != "https://vaultx-crypto.kms.uk-london-1.oraclecloud.com" ||
		b.Region != "uk-london-1" || b.CiphertextB64 == "" {
		t.Fatalf("blob fields: %+v", b)
	}
}

func TestFakeModeDefaultsEmptyConfig(t *testing.T) {
	// sops plugins verify encrypts with no config at all; fake mode must
	// still produce a working round trip
	h := &KMSHandler{Fake: true, WarnWriter: io.Discard}
	wrapped, keyRef, err := h.Encrypt(nil, rampProbe())
	if err != nil {
		t.Fatal(err)
	}
	if keyRef != fakeKeyID {
		t.Fatalf("key_ref = %q, want %q", keyRef, fakeKeyID)
	}
	back, err := h.Decrypt(wrapped)
	if err != nil || string(back) != string(rampProbe()) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestFakeModeForcesFakeKeyEvenWithRealConfig(t *testing.T) {
	h := &KMSHandler{Fake: true, WarnWriter: io.Discard}
	real := "ocid1.key.oc1.eu-frankfurt-1.realvault.realkey"
	wrapped, keyRef, err := h.Encrypt(map[string]any{
		"key_id":          real,
		"crypto_endpoint": "https://realvault-crypto.kms.eu-frankfurt-1.oraclecloud.com",
	}, rampProbe())
	if err != nil {
		t.Fatal(err)
	}
	if keyRef == real || keyRef != fakeKeyID {
		t.Fatalf("key_ref = %q, fake mode must never report a real OCID", keyRef)
	}
	payload, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, BlobPrefix))
	var b blob
	json.Unmarshal(payload, &b)
	if b.KeyID != fakeKeyID || b.CryptoEndpoint != fakeEndpoint {
		t.Fatalf("blob must carry the fake key/endpoint, got %+v", b)
	}
}

func TestFakeModeWarnsOnStderr(t *testing.T) {
	var buf bytes.Buffer
	h := &KMSHandler{Fake: true, WarnWriter: &buf}
	wrapped, _, err := h.Encrypt(nil, rampProbe())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Decrypt(wrapped); err != nil {
		t.Fatal(err)
	}
	warned := strings.Count(buf.String(), "FAKE KMS")
	if warned != 2 {
		t.Fatalf("want one warning per fake operation (2), got %d: %q", warned, buf.String())
	}
}

func TestRealModeRequiresConfig(t *testing.T) {
	h := &KMSHandler{}
	for _, config := range []map[string]any{
		nil,
		{"key_id": "ocid1.key.oc1.r.v.k"},
		{"crypto_endpoint": "https://x"},
		{"key_id": 42, "crypto_endpoint": "https://x"},
	} {
		if _, _, err := h.Encrypt(config, rampProbe()); err == nil {
			t.Fatalf("config %v must fail", config)
		} else if we := wireErr(t, err); we.Code != CodeConfigError {
			t.Fatalf("code = %s, want config_error", we.Code)
		}
	}
}

func TestDecryptRejectsForeignAndCorruptBlobs(t *testing.T) {
	h := &KMSHandler{Fake: true, WarnWriter: io.Discard}
	for _, wrapped := range []string{
		"",
		"sops-conformance-bogus.v1.!!!!!",
		"ocikms.v1.!!!not-base64!!!",
		"ocikms.v1." + base64.StdEncoding.EncodeToString([]byte("not json")),
		"ocikms.v1." + base64.StdEncoding.EncodeToString([]byte(`{"ciphertext":"YQ=="}`)), // no keyId
		"ocikms.v2." + base64.StdEncoding.EncodeToString([]byte(`{}`)),
	} {
		if _, err := h.Decrypt(wrapped); err == nil {
			t.Fatalf("blob %q must fail", wrapped)
		} else if we := wireErr(t, err); we.Code != CodeInvalidRequest {
			t.Fatalf("blob %q: code = %s, want invalid_request", wrapped, we.Code)
		}
	}
}

func TestEncryptRejectsEmptyPlaintext(t *testing.T) {
	h := &KMSHandler{Fake: true, WarnWriter: io.Discard}
	if _, _, err := h.Encrypt(map[string]any{"key_id": "k", "crypto_endpoint": "e"}, nil); err == nil {
		t.Fatal("empty plaintext must fail")
	} else if wireErr(t, err).Code != CodeInvalidRequest {
		t.Fatal("want invalid_request")
	}
}

// validEndpoint satisfies validateEndpoint so client-scripted tests reach
// the KMS call instead of tripping endpoint validation.
const validEndpoint = "https://vaultx-crypto.kms.uk-london-1.oraclecloud.com"

func TestEncryptRejectsDisallowedEndpoints(t *testing.T) {
	h := handlerWithClient(fakeKMS{}, nil)
	for _, endpoint := range []string{
		"https://vaultx-crypto.kms.uk-london-1.oraclecloud.com", // control: passes
		"http://127.0.0.1:12345",                                // loopback simulator
		"https://localhost:1",
		"http://[::1]:1",
	} {
		if _, _, err := h.Encrypt(map[string]any{"key_id": "k", "crypto_endpoint": endpoint}, rampProbe()); err != nil {
			t.Fatalf("endpoint %q must pass: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"http://evil.example",                           // not https
		"https://evil.example",                          // not oraclecloud
		"https://evil.oraclecloud.com.attacker.example", // suffix trick
		"https://oraclecloud.com",                       // apex, not a subdomain
		"e",                                             // not a URL
		"https://",                                      // no host
	} {
		_, _, err := h.Encrypt(map[string]any{"key_id": "k", "crypto_endpoint": endpoint}, rampProbe())
		we := wireErr(t, err)
		if we.Code != CodeConfigError {
			t.Fatalf("endpoint %q: code = %s, want config_error", endpoint, we.Code)
		}
		if !strings.Contains(we.Message, endpoint) {
			t.Fatalf("message %q does not name the rejected endpoint", we.Message)
		}
	}
}

func TestDecryptRejectsDisallowedBlobEndpoints(t *testing.T) {
	h := handlerWithClient(fakeKMS{}, nil)
	for _, endpoint := range []string{"https://evil.example", "http://evil.example"} {
		blobJSON, _ := json.Marshal(blob{
			KeyID:          "ocid1.key.oc1.r.v.k",
			CryptoEndpoint: endpoint,
			Region:         "r",
			CiphertextB64:  "Y2lwaGVydGV4dA==",
		})
		_, err := h.Decrypt(BlobPrefix + base64.StdEncoding.EncodeToString(blobJSON))
		we := wireErr(t, err)
		if we.Code != CodeInvalidRequest {
			t.Fatalf("endpoint %q: code = %s, want invalid_request", endpoint, we.Code)
		}
		if !strings.Contains(we.Message, endpoint) {
			t.Fatalf("message %q does not name the rejected endpoint", we.Message)
		}
	}
}

// Stunt-free cap coverage: a misbehaving backend must not push an ok:true
// response line over the host's 1MiB cap from either direction, so both
// oversized answers are rejected as internal on every CI run, no simulator.
func TestEncryptCapsOversizedCiphertext(t *testing.T) {
	h := handlerWithClient(fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
		return strings.Repeat("A", maxCiphertextB64Len+1), nil
	}}, nil)
	_, _, err := h.Encrypt(map[string]any{"key_id": "k", "crypto_endpoint": validEndpoint}, rampProbe())
	we := wireErr(t, err)
	if we.Code != CodeInternal {
		t.Fatalf("code = %s, want internal", we.Code)
	}
	if !strings.Contains(we.Message, "oversized ciphertext") {
		t.Fatalf("message %q does not name the oversized ciphertext", we.Message)
	}
}

func TestDecryptCapsOversizedPlaintext(t *testing.T) {
	blobJSON, _ := json.Marshal(blob{
		KeyID:          "ocid1.key.oc1.r.v.k",
		CryptoEndpoint: "https://v-crypto.kms.r.oraclecloud.com",
		Region:         "r",
		CiphertextB64:  "Y2lwaGVydGV4dA==",
	})
	h := handlerWithClient(fakeAPI{decrypt: func(context.Context, string, string) (string, error) {
		return base64.StdEncoding.EncodeToString(make([]byte, maxPlaintextB64Len+1)), nil
	}}, nil)
	_, err := h.Decrypt(BlobPrefix + base64.StdEncoding.EncodeToString(blobJSON))
	we := wireErr(t, err)
	if we.Code != CodeInternal {
		t.Fatalf("code = %s, want internal", we.Code)
	}
	if !strings.Contains(we.Message, "oversized plaintext") {
		t.Fatalf("message %q does not name the oversized plaintext", we.Message)
	}
}

// fakeAPI scripts client-level behavior for the mapping tests. Errors are
// wrapped exactly like realKMS wraps them (%w through fmt.Errorf), so the
// classification tests run through the same wrapping the real path produces;
// a classifier that stopped at the first wrap would fail here too.
type fakeAPI struct {
	encrypt func(ctx context.Context, keyID, ptB64 string) (string, error)
	decrypt func(ctx context.Context, keyID, ctB64 string) (string, error)
}

func (f fakeAPI) Encrypt(ctx context.Context, keyID, ptB64 string) (string, error) {
	ct, err := f.encrypt(ctx, keyID, ptB64)
	if err != nil {
		return "", fmt.Errorf(encryptWrapFormat, err)
	}
	return ct, nil
}

func (f fakeAPI) Decrypt(ctx context.Context, keyID, ctB64 string) (string, error) {
	pt, err := f.decrypt(ctx, keyID, ctB64)
	if err != nil {
		return "", fmt.Errorf(decryptWrapFormat, err)
	}
	return pt, nil
}

// svcErr implements common.ServiceError so classify sees a real SDK shape.
type svcErr struct {
	status int
	code   string
	msg    string
}

func (e svcErr) Error() string {
	return fmt.Sprintf("service error %d %s: %s", e.status, e.code, e.msg)
}
func (e svcErr) GetHTTPStatusCode() int { return e.status }
func (e svcErr) GetMessage() string     { return e.msg }
func (e svcErr) GetCode() string        { return e.code }
func (e svcErr) GetOpcRequestID() string {
	return ""
}

func handlerWithClient(api kmsAPI, ctorErr error) *KMSHandler {
	return &KMSHandler{
		newClient: func(context.Context, string) (kmsAPI, error) { return api, ctorErr },
	}
}

func TestErrorMapping(t *testing.T) {
	config := map[string]any{"key_id": "k", "crypto_endpoint": validEndpoint}
	cases := []struct {
		name string
		api  kmsAPI
		ctor error
		want string
	}{
		{
			name: "401 maps to auth_failed",
			api: fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
				return "", svcErr{status: 401, code: "NotAuthenticated"}
			}},
			want: CodeAuthFailed,
		},
		{
			name: "403 maps to auth_failed",
			api: fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
				return "", svcErr{status: 403, code: "NotAuthorizedOrNotFound"}
			}},
			want: CodeAuthFailed,
		},
		{
			name: "404 maps to key_unavailable",
			api: fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
				return "", svcErr{status: 404, code: "NotFound"}
			}},
			want: CodeKeyUnavailable,
		},
		{
			name: "429 throttling maps to key_unavailable",
			api: fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
				return "", svcErr{status: 429, code: "TooManyRequests"}
			}},
			want: CodeKeyUnavailable,
		},
		{
			name: "500 maps to key_unavailable",
			api: fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
				return "", svcErr{status: 500, code: "InternalServerError"}
			}},
			want: CodeKeyUnavailable,
		},
		{
			name: "400 rejected input maps to invalid_request",
			api: fakeAPI{encrypt: func(context.Context, string, string) (string, error) {
				return "", svcErr{status: 400, code: "InvalidParameter"}
			}},
			want: CodeInvalidRequest,
		},
		{
			name: "credential chain failure maps to auth_failed",
			api:  fakeAPI{},
			// wrapped the same way newRealKMS wraps the sentinel
			ctor: fmt.Errorf("%w: chain empty", errNoCredentials),
			want: CodeAuthFailed,
		},
		{
			name: "unknown failure maps to internal",
			api:  fakeAPI{encrypt: func(context.Context, string, string) (string, error) { return "", errors.New("surprise") }},
			want: CodeInternal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := handlerWithClient(tc.api, tc.ctor)
			if _, _, err := h.Encrypt(config, rampProbe()); err == nil {
				t.Fatal("expected an error")
			} else if we := wireErr(t, err); we.Code != tc.want {
				t.Fatalf("code = %s, want %s", we.Code, tc.want)
			}
		})
	}
}

// TestDeadlineExpiryMapsToKeyUnavailable proves the per-request deadline is
// actually threaded into the SDK call: a client that blocks until its
// context dies must surface key_unavailable, not hang for the SDK's 60s.
func TestDeadlineExpiryMapsToKeyUnavailable(t *testing.T) {
	h := handlerWithClient(fakeAPI{encrypt: func(ctx context.Context, keyID, ptB64 string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}}, nil)
	h.RequestTimeout = 50 * time.Millisecond
	start := time.Now()
	_, _, err := h.Encrypt(map[string]any{"key_id": "k", "crypto_endpoint": validEndpoint}, rampProbe())
	if we := wireErr(t, err); we.Code != CodeKeyUnavailable {
		t.Fatalf("code = %s, want key_unavailable", we.Code)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("deadline not applied, took %v", elapsed)
	}
}

func TestDecryptErrorMapping(t *testing.T) { // a blob routed at an endpoint whose key is gone
	blobJSON, _ := json.Marshal(blob{
		KeyID:          "ocid1.key.oc1.r.v.k",
		CryptoEndpoint: "https://v-crypto.kms.r.oraclecloud.com",
		Region:         "r",
		CiphertextB64:  "Y2lwaGVydGV4dA==",
	})
	wrapped := BlobPrefix + base64.StdEncoding.EncodeToString(blobJSON)

	h := handlerWithClient(fakeAPI{
		decrypt: func(context.Context, string, string) (string, error) {
			return "", svcErr{status: 404, code: "NotFound", msg: "key not found"}
		},
	}, nil)
	if _, err := h.Decrypt(wrapped); err == nil {
		t.Fatal("expected an error")
	} else if we := wireErr(t, err); we.Code != CodeKeyUnavailable {
		t.Fatalf("code = %s, want key_unavailable", we.Code)
	}
}

// TestRealClientAgainstLocalServer drives the verbatim SDK calls through a
// loopback server: no external network, but real request signing, request
// shaping and response parsing.
func TestRealClientAgainstLocalServer(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	const keyID = "ocid1.key.oc1.fake-region.vault1.key1"
	var gotEncrypt, gotDecrypt []byte
	ptB64 := base64.StdEncoding.EncodeToString(rampProbe())
	ctB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext-bytes"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/20180608/encrypt") {
			gotEncrypt = body
			fmt.Fprintf(w, `{"ciphertext":%q}`, ctB64)
			return
		}
		gotDecrypt = body
		fmt.Fprintf(w, `{"plaintext":%q,"plaintextChecksum":"x"}`, ptB64)
	}))
	defer srv.Close()

	// credentials from the environment alone: the CLI-style env provider is
	// first in the plugin's chain
	t.Setenv("OCI_CLI_TENANCY", "ocid1.tenancy.oc1..test")
	t.Setenv("OCI_CLI_USER", "ocid1.user.oc1..test")
	t.Setenv("OCI_CLI_REGION", "fake-region")
	t.Setenv("OCI_CLI_FINGERPRINT", "aa:bb:cc:dd")
	t.Setenv("OCI_CLI_KEY_FILE", keyPath)
	// keep the default config file provider out of the test
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	h := &KMSHandler{}
	wrapped, keyRef, err := h.Encrypt(map[string]any{
		"key_id":          keyID,
		"crypto_endpoint": srv.URL,
	}, rampProbe())
	if err != nil {
		t.Fatalf("encrypt against local server: %v", err)
	}
	if keyRef != keyID {
		t.Fatalf("key_ref = %q", keyRef)
	}
	var encReq struct {
		KeyID     string `json:"keyId"`
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(gotEncrypt, &encReq); err != nil {
		t.Fatalf("encrypt request body: %v", err)
	}
	if encReq.KeyID != keyID || encReq.Plaintext != ptB64 {
		t.Fatalf("encrypt request shaped wrong: %+v", encReq)
	}

	back, err := h.Decrypt(wrapped)
	if err != nil {
		t.Fatalf("decrypt against local server: %v", err)
	}
	if string(back) != string(rampProbe()) {
		t.Fatalf("round trip mismatch: %q", back)
	}
	var decReq struct {
		KeyID      string `json:"keyId"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(gotDecrypt, &decReq); err != nil {
		t.Fatalf("decrypt request body: %v", err)
	}
	if decReq.KeyID != keyID || decReq.Ciphertext != ctB64 {
		t.Fatalf("decrypt request shaped wrong: %+v", decReq)
	}
}
