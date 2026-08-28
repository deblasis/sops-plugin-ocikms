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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	f.Add(marshal(map[string]any{"keyId": "k", "ciphertext": "c", "fake": true, "extra": []any{1, nil}})) // fake marker + unknown fields
	f.Add(marshal(map[string]any{"keyId": 123, "ciphertext": true}))                                      // wrong field types
	f.Add(marshal(map[string]any{"keyId": "k", "keyId2": "x", "ciphertext": "c\r\n"}))                    // CR/LF inside a field
	f.Add(BlobPrefix + "QQ")                                                                              // base64 length mod 4 == 2: decodes to one byte
	f.Add(BlobPrefix + "QQ=")                                                                             // illegal padding
	f.Add(BlobPrefix + "QQ==")                                                                            // decodes to payload "A": not JSON
	f.Add(BlobPrefix + BlobPrefix + base64.StdEncoding.EncodeToString(valid))
	f.Add("ocikms.v2." + base64.StdEncoding.EncodeToString(valid)) // future prefix must not parse as v1
	f.Fuzz(func(t *testing.T, s string) {
		b, werr := parseWrappedBlob(s)
		if werr != nil {
			if werr.Code != CodeInvalidRequest {
				t.Fatalf("reject %q as %s, want invalid_request", s[:min(len(s), 64)], werr.Code)
			}
			if werr.Message == "" {
				t.Fatalf("rejection of %q carries no message", s[:min(len(s), 64)])
			}
			return
		}
		if b.KeyID == "" || b.CiphertextB64 == "" {
			t.Fatal("accepted blob with empty keyId or ciphertext")
		}
	})
}

// fuzzDecodeSrv is one loopback KMS plus one SDK client per fuzz worker
// process; the fuzz func swaps status/body under the mutex, so every exec
// drives the REAL SDK client through the REAL response-decode and
// error-unmarshal path.
var fuzzDecodeSrv struct {
	once   sync.Once
	client keymanagement.KmsCryptoClient
	mu     sync.Mutex
	status int
	body   []byte
}

func fuzzDecodeClient() keymanagement.KmsCryptoClient {
	fuzzDecodeSrv.once.Do(func() {
		// own listener with retries: httptest.NewServer panics outright when
		// the ephemeral port pool runs dry, and a panic inside a worker gets
		// blamed on whatever input was executing
		var l net.Listener
		var err error
		for i := 0; i < 5; i++ {
			l, err = net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			panic("fuzz loopback listener: " + err.Error())
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fuzzDecodeSrv.mu.Lock()
			defer fuzzDecodeSrv.mu.Unlock()
			w.WriteHeader(fuzzDecodeSrv.status)
			_, _ = w.Write(fuzzDecodeSrv.body)
		}))
		srv.Listener = l
		srv.Start()

		// throwaway in-memory key: the signature is never verified, it only
		// has to make the raw provider happy
		key, kerr := rsa.GenerateKey(rand.Reader, 2048)
		if kerr != nil {
			panic("fuzz keygen: " + kerr.Error())
		}
		pemKey := string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
		provider := common.NewRawConfigurationProvider(
			"ocid1.tenancy.oc1..fuzz", "ocid1.user.oc1..fuzz", "us-fuzz-1",
			"aa:bb:cc:dd", pemKey, nil)
		client, cerr := keymanagement.NewKmsCryptoClientWithConfigurationProvider(provider, srv.URL)
		if cerr != nil {
			panic("fuzz client ctor: " + cerr.Error())
		}
		// one client per process means one keep-alive transport, so a long
		// session does not burn an ephemeral port per exec
		fuzzDecodeSrv.client = client
	})
	return fuzzDecodeSrv.client
}

// FuzzKMSResponseDecode: arbitrary status/body pairs through the verbatim SDK
// client against a loopback server, then classify. No panic, and the result is
// always one of the frozen v1 codes (unmappable -> internal). Both the
// Encrypt and the Decrypt response shapes are driven.
func FuzzKMSResponseDecode(f *testing.F) {
	enc := func(status int64, body []byte) { f.Add(status, body, false) }
	dec := func(status int64, body []byte) { f.Add(status, body, true) }
	enc(401, []byte(`{"code":"NotAuthenticated","message":"no"}`))
	enc(403, []byte(`{"code":"NotAuthorizedOrNotFound","message":"no"}`))
	enc(404, []byte(`{"code":"NotFound","message":"gone"}`))
	enc(429, []byte(`{"code":"TooManyRequests","message":"slow down"}`))
	enc(500, []byte(`{"code":"InternalServerError","message":"boom"}`))
	enc(503, []byte(``))
	enc(400, []byte(`{"code":"InvalidParameter","message":"bad"}`))
	enc(302, []byte(`<html>moved</html>`)) // redirect the client cannot follow -> internal
	enc(200, []byte(`not-json {oops`))     // 200 the SDK cannot parse -> internal
	enc(200, []byte(`{"ciphertext":"YWJj"}`))
	enc(500, []byte{0x00, 0xff, 0xfe})
	enc(418, []byte(`{"code":"Teapot","message":"short and stout"}`)) // parseable non-mapped status -> default arm
	enc(418, []byte(strings.Repeat("teapot ", 1000)))
	dec(200, []byte(`{"plaintext":"YWJj"}`))
	dec(404, []byte(`{"code":"NotFound","message":"gone"}`))
	dec(500, []byte(`{"code":"InternalServerError","message":"boom"}`))
	dec(429, []byte(`{"code":"TooManyRequests","message":"slow"}`))
	dec(200, []byte(`not-json {oops`))

	f.Fuzz(func(t *testing.T, rawStatus int64, body []byte, decrypt bool) {
		// in-range statuses pass through untouched so seeds mean what they
		// say; wild values are folded into 200..599, never below
		status := int(rawStatus)
		if status < 200 || status > 599 {
			status = 200 + int(((rawStatus%400)+400)%400)
		}
		fuzzDecodeSrv.mu.Lock()
		fuzzDecodeSrv.status, fuzzDecodeSrv.body = status, body
		fuzzDecodeSrv.mu.Unlock()

		client := fuzzDecodeClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var err error
		wrap := encryptWrapFormat
		if decrypt {
			wrap = decryptWrapFormat
			_, err = client.Decrypt(ctx, keymanagement.DecryptRequest{
				DecryptDataDetails: keymanagement.DecryptDataDetails{
					KeyId:      common.String("ocid1.key.oc1.fuzz.v.k"),
					Ciphertext: common.String("Y2lwaGVydGV4dA=="),
				},
			})
		} else {
			_, err = client.Encrypt(ctx, keymanagement.EncryptRequest{
				EncryptDataDetails: keymanagement.EncryptDataDetails{
					KeyId:     common.String("ocid1.key.oc1.fuzz.v.k"),
					Plaintext: common.String("Zm9v"),
				},
			})
		}
		if err == nil {
			return // a well-formed success body: nothing to classify
		}
		// wrap exactly like realKMS does, then classify
		we := classify(fmt.Errorf(wrap, err))
		switch we.Code {
		case CodeInvalidRequest, CodeAuthFailed, CodeKeyUnavailable, CodeInternal:
			// frozen taxonomy: classify never escapes it
		default:
			t.Fatalf("status %d body %q classified as unknown code %q", status, body[:min(len(body), 64)], we.Code)
		}
	})
}

// FuzzValidateEndpoint: arbitrary endpoint strings into the SSRF gate. The
// checked property is the SPEC, restated independently of the code: an
// accepted endpoint is https to a *.oraclecloud.com host, or http/https to a
// loopback host, nothing else. Regressions to Contains/prefix matching
// (evil.oraclecloud.com.attacker.example) fail here.
func FuzzValidateEndpoint(f *testing.F) {
	f.Add("https://v-crypto.kms.eu-frankfurt-1.oraclecloud.com")
	f.Add("https://v-crypto.kms.eu-frankfurt-1.oraclecloud.com:443")
	f.Add("http://127.0.0.1:8080")
	f.Add("https://localhost")
	f.Add("http://[::1]:9")
	f.Add("https://evil.oraclecloud.com.attacker.example") // suffix confusion
	f.Add("https://eviloraclecloud.com")                   // substring, no dot
	f.Add("https://attacker.example/oraclecloud.com")      // suffix in the path
	f.Add("http://v-crypto.kms.eu-frankfurt-1.oraclecloud.com")
	f.Add("https://user:pass@127.0.0.1:1")
	f.Add("https://user@evil.example@127.0.0.1")
	f.Add("https://V-CRYPTO.KMS.EU-FRANKFURT-1.ORACLECLOUD.COM")
	f.Add("https://oraclecloud.com") // apex, not a subdomain
	f.Add("https://x.oraclecloud.com.evil.example")
	f.Add("ftp://v-crypto.kms.eu-frankfurt-1.oraclecloud.com")
	f.Add("//v-crypto.kms.eu-frankfurt-1.oraclecloud.com")
	f.Add("https://127.0.0.1.evil.example")
	f.Add("https://[::ffff:127.0.0.1]/")
	f.Add("unix:///tmp/sock")
	f.Add("https://127.0.0.1\n")
	f.Add("")
	f.Add("https://xn--evil.oraclecloud.com")
	f.Fuzz(func(t *testing.T, endpoint string) {
		if err := validateEndpoint(endpoint); err != nil {
			return
		}
		u, perr := url.Parse(endpoint)
		if perr != nil {
			t.Fatalf("accepted %q, which does not even parse", endpoint)
		}
		host := strings.ToLower(u.Hostname())
		loopback := (u.Scheme == "http" || u.Scheme == "https") &&
			(host == "127.0.0.1" || host == "::1" || host == "localhost")
		cloud := u.Scheme == "https" && strings.HasSuffix(host, oracleCloudSuffix)
		if !loopback && !cloud {
			t.Fatalf("accepted endpoint outside the allowed host families: %q", endpoint)
		}
	})
}

// fuzzServiceError is the smallest common.ServiceError implementation; the
// SDK concrete type carries the same four getters, so a synthetic lets the
// fuzzer own status/code/message without HTTP.
type fuzzServiceError struct {
	status  int
	code    string
	message string
}

func (e fuzzServiceError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.status, e.code, e.message)
}
func (e fuzzServiceError) GetHTTPStatusCode() int  { return e.status }
func (e fuzzServiceError) GetMessage() string      { return e.message }
func (e fuzzServiceError) GetCode() string         { return e.code }
func (e fuzzServiceError) GetOpcRequestID() string { return "fuzz" }

// fuzzNetError satisfies net.Error so the unreachable-endpoint arm runs
// without a socket.
type fuzzNetError struct{ msg string }

func (e fuzzNetError) Error() string   { return e.msg }
func (e fuzzNetError) Timeout() bool   { return true }
func (e fuzzNetError) Temporary() bool { return true }

// FuzzClassify: synthetic wrapped errors straight into classify, no HTTP. The
// loopback target exercises the real SDK decode path but cannot force
// no-credentials or a dead network; this one pins the full mapping table.
func FuzzClassify(f *testing.F) {
	f.Add(uint8(0), int32(401), "NotAuthenticated", "no")
	f.Add(uint8(0), int32(403), "NotAuthorizedOrNotFound", "no")
	f.Add(uint8(0), int32(404), "NotFound", "gone")
	f.Add(uint8(0), int32(429), "TooManyRequests", "slow")
	f.Add(uint8(0), int32(500), "InternalServerError", "boom")
	f.Add(uint8(0), int32(503), "", "")
	f.Add(uint8(0), int32(400), "InvalidParameter", "bad")
	f.Add(uint8(0), int32(418), "Teapot", "short and stout")
	f.Add(uint8(0), int32(100), "Continue", "weird but service-shaped")
	f.Add(uint8(1), int32(0), "", "no config file")
	f.Add(uint8(2), int32(0), "", "dial tcp: i/o timeout")
	f.Add(uint8(3), int32(0), "", "anything else")
	f.Fuzz(func(t *testing.T, kind uint8, status int32, code, msg string) {
		var err error
		want := CodeInternal
		switch kind % 4 {
		case 0:
			err = fmt.Errorf(decryptWrapFormat, fuzzServiceError{int(status), code, msg})
			want = "" // per-status, asserted below
		case 1:
			err = fmt.Errorf("%w: %s", errNoCredentials, msg)
			want = CodeAuthFailed
		case 2:
			err = fmt.Errorf(encryptWrapFormat, fuzzNetError{msg})
			want = CodeKeyUnavailable
		case 3:
			err = fmt.Errorf(encryptWrapFormat, errors.New(msg))
		}
		we := classify(err)
		if we == nil || we.Code == "" {
			t.Fatalf("classify(%v) returned no code", err)
		}
		if want == "" {
			switch s := int(status); {
			case s == 401 || s == 403:
				want = CodeAuthFailed
			case s == 404 || s == 429 || s >= 500:
				want = CodeKeyUnavailable
			case s == 400:
				want = CodeInvalidRequest
			default:
				want = CodeInternal
			}
		}
		if we.Code != want {
			t.Fatalf("classify(%v) = %s, want %s", err, we.Code, want)
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
	f.Add([]byte(hs + "{\"id\":4,\"action\":\"decrypt\",\"wrapped\":\"ocikms.v1.GARBAGE\"}\n"))
	f.Add([]byte(hs + "{\"id\":5,\"action\":\"encrypt\",\"plaintext\":12345}\n")) // plaintext not base64
	f.Add([]byte("{\"protocol\":\"sops-plugin\",\"max_version\":0}\n"))           // too-old host
	f.Add([]byte(hs))
	f.Add([]byte(strings.ReplaceAll(hs, "\n", "\r\n"))) // CRLF leniency
	// plaintext big enough that the fake ciphertext base64 crosses the
	// 128 KiB outbound cap: exercises the oversized-ciphertext rejection,
	// unreachable by luck because the line must stay under the 1 MiB cap
	f.Add([]byte(hs + "{\"id\":6,\"action\":\"encrypt\",\"plaintext\":\"" + strings.Repeat("QUFB", 200000) + "\"}\n"))

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
