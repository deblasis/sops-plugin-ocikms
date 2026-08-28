# sops-plugin-ocikms

A [sops](https://github.com/getsops/sops) encryption plugin for Oracle Cloud
Infrastructure Key Management, speaking the sops-plugin/1 protocol. This is
the reference third-party plugin for the protocol RFC; the OCI credential
chain and the KMS Encrypt/Decrypt calls are ported from the sops OCI KMS
provider (PR #1226).

The plugin wraps and unwraps sops' 32-byte data key with an OCI KMS key. The
wrapped value stored in file metadata is:

    ocikms.v1.<std-base64 of JSON {"keyId","cryptoEndpoint","region","ciphertext"}>

so decryption needs only the blob plus whatever credentials the runtime
environment provides (OCI_CLI_* or OCI_* env vars, ~/.oci/config, or instance
principals, tried in that order). No config file is required at decrypt time.

## Install

    go install github.com/deblasis/sops-plugin-ocikms/cmd/sops-plugin-ocikms@latest

The binary must be named `sops-plugin-ocikms` and reachable on PATH.

## Allowlist

Executing plugins is gated by your local `~/.sops.yaml` (never the repo's):

```yaml
plugins:
  allowed:
    - ocikms
```

## .sops.yaml snippet

```yaml
creation_rules:
  - path_regex: secrets/.*$
    plugins:
      - binary: ocikms
        key_ref: ocid1.key.oc1.eu-frankfurt-1.yourvault.yourkey
        config:
          key_id: ocid1.key.oc1.eu-frankfurt-1.yourvault.yourkey
          crypto_endpoint: https://yourvault-crypto.kms.eu-frankfurt-1.oraclecloud.com
```

`config` must never contain credentials; it carries only the key OCID and the
vault crypto endpoint.

## Verify

Check protocol conformance against your sops build:

    SOPS_OCIKMS_FAKE_KMS=1 sops plugins verify "$(command -v sops-plugin-ocikms)"

Without OCI credentials the real encrypt/decrypt cannot run, so set
`SOPS_OCIKMS_FAKE_KMS=1`: the plugin then uses an in-process fake KMS
(SHA-256 keystream XOR, NOT cryptography, never for real secrets) instead of
the network. Fake mode is loud and distinguishable: it always wraps under a
fixed fake key id and endpoint (`ocid1.key.oc1.fake-region.fakevault.fakekey`),
ignoring whatever the config carries, so a fake blob is identifiable by its
key_ref and never masquerades as a real OCID; and it prints a one-line warning
to stderr on every fake wrap and unwrap. This env var exists only as a testing
hook; without it the plugin always talks to real OCI KMS.

## Credentials at runtime

The chain, in order: OCI_CLI_* env vars (OCI_CLI_TENANCY, OCI_CLI_USER,
OCI_CLI_REGION, OCI_CLI_FINGERPRINT, OCI_CLI_KEY_FILE), native SDK env vars
(OCI_tenancy_ocid, OCI_user_ocid, OCI_region, OCI_fingerprint,
OCI_private_key_path), the config file named by OCI_CLI_CONFIG_FILE
(optional OCI_CLI_PROFILE), the default ~/.oci/config, and finally instance
principals (lazily, only on OCI compute).

Test-isolation caveat: the SDK's config-file provider resolves the home
directory through the OS user database (os/user), not HOME/USERPROFILE, so
pointing those at an empty dir does NOT hide a real ~/.oci/config on the
machine. Tests that need a credential-free environment skip when a real
config is present.

## Error mapping

OCI failure to frozen protocol code: 401/403 -> auth_failed, 404/429/5xx and
network timeouts -> key_unavailable, 400 -> invalid_request, missing
key_id/crypto_endpoint in config -> config_error, anything else -> internal.

## Development

    go test ./... -race -count=1
    go build -ldflags "-X main.pluginVersion=1.2.3" -o sops-plugin-ocikms ./cmd/sops-plugin-ocikms

Requires Go 1.25 or newer.

### Fuzzing

Three native fuzz targets live in fuzz_test.go; their seed corpora run as
plain tests on every `go test`. Deepen each with:

    go test -run '^$' -fuzz FuzzParseWrappedBlob -fuzztime 60s .
    go test -run '^$' -fuzz FuzzKMSResponseDecode -fuzztime 60s .
    go test -run '^$' -fuzz FuzzProtocolLoop -fuzztime 60s .

- FuzzParseWrappedBlob: arbitrary strings into the wrapped-blob parser; every
  rejection must be invalid_request, never a panic.
- FuzzKMSResponseDecode: arbitrary status/body pairs through the verbatim OCI
  SDK client against a loopback server, then classify; the result must stay
  inside the frozen code taxonomy.
- FuzzProtocolLoop: arbitrary bytes as the whole stdin stream of an in-process
  Serve; it must terminate, emit only valid JSON lines, and never answer
  ok:true with empty payload fields.

CI note: regular CI runs the seed corpora only (cheap); schedule the
-fuzztime runs as a separate periodic job, not per commit.

## OCI KMS simulator (ocisim)

`ocisim/` is an adversarial test stand-in for OCI KMS, built as a
[stunt](https://github.com/stuntapi/stunt) adapter (`go install
stuntapi.com/stunt/cmd/stunt@latest`). The `ocisim` package boots the adapter
on a loopback port and flips failure modes over stunt's dashboard HTTP API, so
Go tests drive injection programmatically. `go test ./ocisim/` runs the real
plugin binary (fake mode OFF) against it: signed requests, stateful
encrypt/decrypt round trips, multiple keys, unknown-key 404s, and failure
injection (auth-401, auth-403, key-gone-404, throttled-429 with Retry-After,
outage-500, unavailable-503, flap, garbage 200s, oversized payloads,
slow-500-3s, hang). The 30s hang boundary test runs only with OCISIM_SLOW=1.

The adversarial battery (ocisim/battery_test.go) layers ten scenarios on the
same harness: auth rejection and recovery, sustained throttling with a
server-side request counter proving no retry storm, ten flap cycles,
count-bounded faults (throttle-N, burst-garbage-N: the first N calls fail,
then healthy; counters live in KV, Reset re-arms them), malformed successes
(a >1MiB ciphertext is emitted fine but rejected by the plugin's inbound
1MiB line cap when fed back as a decrypt request), slow failures on both
paths, credential-free startup, cross-simulator endpoint mismatch and
wrong-key blobs, mid-sequence flaps, and rapid profile switching with
process-leak checks. Default suite stays under ~30s.

Auth is stub-level: request signatures are accepted but never validated, so
401/403 come from profiles, not signature checks. Known key OCIDs are
`ocid1.key.oc1.sim-region.simvault.simkey1` and `...simkey2`. Tests skip when
the stunt binary is absent (STUNT_BIN overrides the PATH lookup).

## License

MPL-2.0, see LICENSE. The ported provider logic derives from
getsops/sops PR #1226 (MPL-2.0). The OCI Go SDK is dual licensed
UPL-1.0 / Apache-2.0.
