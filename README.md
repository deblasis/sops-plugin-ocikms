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
the network. This env var exists only as a testing hook; without it the plugin
always talks to real OCI KMS.

## Credentials at runtime

The chain, in order: OCI_CLI_* env vars (OCI_CLI_TENANCY, OCI_CLI_USER,
OCI_CLI_REGION, OCI_CLI_FINGERPRINT, OCI_CLI_KEY_FILE), native SDK env vars
(OCI_tenancy_ocid, OCI_user_ocid, OCI_region, OCI_fingerprint,
OCI_private_key_path), the config file named by OCI_CLI_CONFIG_FILE
(optional OCI_CLI_PROFILE), the default ~/.oci/config, and finally instance
principals (lazily, only on OCI compute).

## Error mapping

OCI failure to frozen protocol code: 401/403 -> auth_failed, 404/429/5xx and
network timeouts -> key_unavailable, 400 -> invalid_request, missing
key_id/crypto_endpoint in config -> config_error, anything else -> internal.

## License

The ported provider logic derives from sops (MPL-2.0). The OCI Go SDK is dual
licensed UPL-1.0 / Apache-2.0.
