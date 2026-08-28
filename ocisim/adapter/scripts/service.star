# OCI KMS crypto endpoint handlers: stateful encrypt/decrypt over the keys
# collection and a ciphertext->plaintext KV map, plus adapter-authored
# degraded modes read via profile_active().

def on_encrypt(req):
    mode = profile_active()
    if mode == "garbage":
        # raw string body: 200 that no JSON client can parse
        return respond(200, "not-json {oops")
    if mode == "oversized":
        return respond(200, {"ciphertext": "A" * 1100000})
    if mode == "flap" and _flap_fails():
        return _err(500, "InternalServerError", "simulated flap")
    bounded = _bounded(mode)
    if bounded != None:
        kind, n = bounded
        cnt = store_kv_incr("kms", "bounded-" + kind + "-" + str(n))
        if cnt <= n:
            if kind == "throttle":
                # the count rides in the message so tests can prove the client
                # made exactly one request per operation (no retry storm)
                return _err(429, "TooManyRequests", "simulated throttling (request " + str(cnt) + ")")
            return respond(200, "not-json {oops")

    body = req.get("body")
    if body == None:
        body = {}
    key_id = body.get("keyId", "")
    plaintext = body.get("plaintext", "")
    if type(key_id) != "string" or key_id == "":
        return _err(400, "InvalidParameter", "keyId is required")
    if type(plaintext) != "string" or plaintext == "":
        return _err(400, "InvalidParameter", "plaintext is required")
    if _find_key(key_id) == None:
        return _err(404, "NotFound", "The key " + key_id + " does not exist")

    seq = store_kv_incr("kms", "seq")
    ct = "ocisim-" + _world() + "-" + str(seq)
    store_kv_set("blobs", ct, plaintext)
    store_kv_set("blobkeys", ct, key_id)
    return respond(200, {"ciphertext": ct})

def on_decrypt(req):
    mode = profile_active()
    if mode == "garbage":
        return respond(200, "not-json {oops")
    if mode == "flap" and _flap_fails():
        return _err(500, "InternalServerError", "simulated flap")
    bounded = _bounded(mode)
    if bounded != None:
        kind, n = bounded
        cnt = store_kv_incr("kms", "bounded-" + kind + "-" + str(n))
        if cnt <= n:
            if kind == "throttle":
                return _err(429, "TooManyRequests", "simulated throttling (request " + str(cnt) + ")")
            return respond(200, "not-json {oops")

    body = req.get("body")
    if body == None:
        body = {}
    ct = body.get("ciphertext", "")
    key_id = body.get("keyId", "")
    if type(ct) != "string" or ct == "":
        return _err(400, "InvalidParameter", "ciphertext is required")
    if type(key_id) != "string" or key_id == "":
        return _err(400, "InvalidParameter", "keyId is required")
    if _find_key(key_id) == None:
        return _err(404, "NotFound", "The key " + key_id + " does not exist")
    # a ciphertext minted under an earlier world (pre-reset) must not resolve
    # even if its KV entry somehow survived the wipe
    if _ct_gen(ct) != _world():
        return _err(404, "NotFound", "unknown ciphertext")
    pt = store_kv_get("blobs", ct)
    if pt == None:
        return _err(404, "NotFound", "unknown ciphertext")
    # bind ciphertext to its key like real KMS: the ciphertext is known but
    # routed at the wrong key, so the request itself is wrong, not the key
    # (400 invalid_request, not 404)
    if store_kv_get("blobkeys", ct) != key_id:
        return _err(400, "InvalidParameter", "ciphertext was not encrypted with key " + key_id)
    return respond(200, {"plaintext": pt, "plaintextChecksum": "simulated"})

def _flap_fails():
    # persisted in KV so the alternation holds across plugin processes
    return store_kv_incr("kms", "flap") % 2 == 1

# count-bounded modes: throttle-<n> answers 429 (with the request count in the
# message) and burst-garbage-<n> answers a non-JSON 200 for the first n
# handler calls, then behaves healthy. The counter persists in KV, so a test
# that re-arms the same bound must Reset first (the same contract as flap).
def _bounded(mode):
    # profile_active() is None when no profile is live
    if type(mode) != "string":
        return None
    if mode.startswith("throttle-"):
        n = int(mode[len("throttle-"):])
        if n > 0:
            return ("throttle", n)
    if mode.startswith("burst-garbage-"):
        n = int(mode[len("burst-garbage-"):])
        if n > 0:
            return ("garbage", n)
    return None

_SEED_KEYS = [
    "ocid1.key.oc1.sim-region.simvault.simkey1",
    "ocid1.key.oc1.sim-region.simvault.simkey2",
]

# Synthetic P-256 key, entropy faucet only: ECDSA signatures draw their nonce
# from the host's crypto/rand, so signing the same string twice yields two
# different signatures. Signs nothing, guards nothing.
_MINT_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJxd+FjJ95yhhWRTA
TuNMZAJjXzG1pLwZllBuHmyIT7+hRANCAAQ3eS38Nu+TIxlCzRE8k2E8/eGdpERB
GGtdgkMShf2rsuCo1GopDFz6ajQDVf9EGtruOsCYhklUqayU9ixyCRTr
-----END PRIVATE KEY-----"""

def _world():
    # ciphertext names embed a world generation. Reset clears collections, so
    # the world doc vanishes and a fresh gen is minted: pre-reset ciphertexts
    # then 404 even if their KV entries somehow survived the reset, and the
    # rewound seq counter cannot collide with old names. The mint mixes the
    # randomized ECDSA signature (real entropy, so back-to-back mints in the
    # same wall-clock second still diverge) with clock+seq as fallback
    # sources in case signing ever turns deterministic.
    c = store_collection("world")
    doc = c.get("world")
    if doc == None:
        seq = store_kv_incr("kms", "seq")
        sig = crypto.ecdsa_sign_p256(_MINT_KEY, str(clock.now_unix()) + ":" + str(seq))
        gen = sig[:16]
        c.insert({"id": "world", "gen": gen})
        return gen
    return doc.get("gen", "")

def _ct_gen(ct):
    parts = ct.split("-")
    if len(parts) != 3:
        return None
    return parts[1]

def _find_key(key_id):
    c = store_collection("keys")
    docs = c.list()
    if len(docs) == 0:
        # state reset (dashboard /api/state reset) wipes collections without
        # re-running seeding; re-materialize so a reset server acts fresh
        for k in _SEED_KEYS:
            c.insert({"id": k, "state": "ENABLED"})
        docs = c.list()
    for doc in docs:
        if doc.get("id", "") == key_id:
            return doc
    return None

def _err(status, code, message):
    # OCI SDK error shape: code+message in the body, non-2xx status
    return respond(status, {"code": code, "message": message})
