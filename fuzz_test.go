package ocikms

// Native fuzz targets (P17). Each runs its seed corpus on every `go test`;
// deepen with e.g. `go test -run '^$' -fuzz FuzzParseWrappedBlob -fuzztime 60s`.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// FuzzParseWrappedBlob: arbitrary strings into the blob parser. No panic, and
// every rejection is invalid_request (a corrupt blob is a client problem,
// never a backend failure).
func FuzzParseWrappedBlob(f *testing.F) {
	valid, _ := json.Marshal(blob{
		KeyID:          "ocid1.key.oc1.r.v.k",
		CryptoEndpoint: "https://v-crypto.kms.r.oraclecloud.com",
		Region:         "r",
		CiphertextB64:  "Y2lwaGVydGV4dA==",
	})
	marshal := func(v any) string {
		b, _ := json.Marshal(v)
		return BlobPrefix + base64.StdEncoding.EncodeToString(b)
	}
	f.Add(BlobPrefix + base64.StdEncoding.EncodeToString(valid))
	f.Add(BlobPrefix + "Y2lwaGVydGV4") // truncated base64
	f.Add(BlobPrefix + base64.StdEncoding.EncodeToString([]byte("not json at all")))
	f.Add(marshal(map[string]any{"keyId": "k"}))                              // missing ciphertext
	f.Add(marshal(map[string]any{"keyId": "a\x00b", "ciphertext": "c\x00d"})) // embedded NULs
	f.Add(marshal(map[string]any{"keyId": "ключ", "ciphertext": "暗号"}))       // unicode
	f.Add(BlobPrefix + strings.Repeat("A", 1<<16))                            // huge
	f.Add("age1 WrongPrefix")
	f.Add("")
	f.Add(BlobPrefix)
	f.Fuzz(func(t *testing.T, s string) {
		b, werr := parseWrappedBlob(s)
		if werr != nil {
			if werr.Code != CodeInvalidRequest {
				t.Fatalf("reject %q as %s, want invalid_request", s[:min(len(s), 64)], werr.Code)
			}
			return
		}
		if b.KeyID == "" || b.CiphertextB64 == "" {
			t.Fatal("accepted blob with empty keyId or ciphertext")
		}
	})
}

// fuzzDecodeSrv is one loopback KMS per fuzz worker process; the fuzz func
// swaps status/body under the mutex, so every exec drives the REAL SDK client
// through the REAL response-decode and error-unmarshal path.
var fuzzDecodeSrv struct {
	once   sync.Once
	url    string
	mu     sync.Mutex
	status int
	body   []byte
}

func fuzzDecodeEndpoint() string {
	fuzzDecodeSrv.once.Do(func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fuzzDecodeSrv.mu.Lock()
			defer fuzzDecodeSrv.mu.Unlock()
			w.WriteHeader(fuzzDecodeSrv.status)
			_, _ = w.Write(fuzzDecodeSrv.body)
		}))
		fuzzDecodeSrv.url = srv.URL
	})
	return fuzzDecodeSrv.url
}

// FuzzKMSResponseDecode: arbitrary status/body pairs through the verbatim SDK
// client against a loopback server, then classify. No panic, and the result is
// always one of the frozen v1 codes (unmappable -> internal).
func FuzzKMSResponseDecode(f *testing.F) {
	f.Add(int64(401), []byte(`{"code":"NotAuthenticated","message":"no"}`))
	f.Add(int64(403), []byte(`{"code":"NotAuthorizedOrNotFound","message":"no"}`))
	f.Add(int64(404), []byte(`{"code":"NotFound","message":"gone"}`))
	f.Add(int64(429), []byte(`{"code":"TooManyRequests","message":"slow down"}`))
	f.Add(int64(500), []byte(`{"code":"InternalServerError","message":"boom"}`))
	f.Add(int64(503), []byte(``))
	f.Add(int64(400), []byte(`{"code":"InvalidParameter","message":"bad"}`))
	f.Add(int64(302), []byte(`<html>moved</html>`)) // unmappable status -> internal
	f.Add(int64(200), []byte(`not-json {oops`))     // 200 the SDK cannot parse -> internal
	f.Add(int64(200), []byte(`{"ciphertext":"YWJj"}`))
	f.Add(int64(500), []byte{0x00, 0xff, 0xfe})
	f.Add(int64(418), []byte(strings.Repeat("teapot ", 1000)))

	// throwaway in-memory key: the signature is never verified, it only has
	// to make the raw provider happy
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	provider := common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..fuzz", "ocid1.user.oc1..fuzz", "us-fuzz-1",
		"aa:bb:cc:dd", pemKey, nil)

	f.Fuzz(func(t *testing.T, rawStatus int64, body []byte) {
		// ((x%400)+400)%400 keeps negatives in range, so the harness really
		// covers 200..599 as documented
		status := 200 + int(((rawStatus%400)+400)%400)
		fuzzDecodeSrv.mu.Lock()
		fuzzDecodeSrv.status, fuzzDecodeSrv.body = status, body
		fuzzDecodeSrv.mu.Unlock()

		client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(provider, fuzzDecodeEndpoint())
		if err != nil {
			t.Fatalf("client ctor: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = client.Encrypt(ctx, keymanagement.EncryptRequest{
			EncryptDataDetails: keymanagement.EncryptDataDetails{
				KeyId:     common.String("ocid1.key.oc1.fuzz.v.k"),
				Plaintext: common.String("Zm9v"),
			},
		})
		if err == nil {
			return // a well-formed success body: nothing to classify
		}
		// wrap exactly like realKMS does, then classify
		we := classify(fmt.Errorf(encryptWrapFormat, err))
		switch we.Code {
		case CodeInvalidRequest, CodeAuthFailed, CodeKeyUnavailable, CodeInternal:
			// frozen taxonomy: classify never escapes it
		default:
			t.Fatalf("status %d body %q classified as unknown code %q", status, body[:min(len(body), 64)], we.Code)
		}
	})
}

// lineBudgetReader caps what Serve can consume: bounded bytes and bounded
// lines, then EOF. Keeps a fuzz input that is megabytes of bare LFs from
// turning into megabytes of marshaled responses inside one exec.
type lineBudgetReader struct {
	r        io.Reader
	maxBytes int
	maxLines int
	bytes    int
	lines    int
}

func (l *lineBudgetReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.bytes += n
	for i := 0; i < n; i++ {
		if p[i] == '\n' {
			l.lines++
		}
	}
	if err == nil && (l.bytes > l.maxBytes || l.lines > l.maxLines) {
		return n, io.EOF
	}
	return n, err
}

// FuzzProtocolLoop: arbitrary bytes as the whole stdin stream of an in-process
// Serve (fake KMS, no subprocess for speed). Serve must terminate, every
// emitted line must be valid JSON, and no input may produce ok:true with both
// payload fields empty.
func FuzzProtocolLoop(f *testing.F) {
	hs := `{"protocol":"sops-plugin","max_version":1}` + "\n"
	fakeWrapped := BlobPrefix + base64.StdEncoding.EncodeToString([]byte(
		`{"keyId":"ocid1.key.oc1.fake-region.fakevault.fakekey","ciphertext":"aGVsbG8="}`))
	f.Add([]byte(hs))
	f.Add([]byte(hs + "{\"id\":1,\"action\":\"encrypt\",\"config\":{\"key_id\":\"k\",\"crypto_endpoint\":\"e\"},\"plaintext\":\"YWJj\"}\n"))
	f.Add([]byte(hs + "{\"id\":2,\"action\":\"decrypt\",\"wrapped\":\"" + fakeWrapped + "\"}\n"))
	f.Add([]byte(hs + "garbage not json\n"))
	f.Add([]byte(hs + "{\"id\":3,\"action\":\"nonsense\"}\n"))
	f.Add([]byte(hs + "\n\n\n"))
	f.Add([]byte("totally wrong handshake\n"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})

	f.Fuzz(func(t *testing.T, stdin []byte) {
		in := &lineBudgetReader{r: bytes.NewReader(stdin), maxBytes: 1 << 20, maxLines: 10000}
		var out bytes.Buffer
		h := &KMSHandler{Fake: true, WarnWriter: io.Discard, RequestTimeout: 100 * time.Millisecond}
		done := make(chan error, 1)
		go func() { done <- Serve(in, &out, h, "fuzz") }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Serve did not terminate within the budget")
		}
		for i, line := range bytes.Split(out.Bytes(), []byte("\n")) {
			if len(line) == 0 {
				continue // the trailing fragment after the final LF
			}
			if !json.Valid(line) {
				t.Fatalf("emitted line %d is not valid JSON: %q", i, line)
			}
			var res response
			if err := json.Unmarshal(line, &res); err != nil {
				continue // the handshake line is a different shape
			}
			if res.OK && res.Wrapped == "" && len(res.Plaintext) == 0 {
				t.Fatalf("ok:true with empty payload fields: %q", line)
			}
		}
	})
}
