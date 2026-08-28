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
    ct = "ocisim-" + str(seq)
    store_kv_set("blobs", ct, plaintext)
    store_kv_set("blobkeys", ct, key_id)
    return respond(200, {"ciphertext": ct})

def on_decrypt(req):
    mode = profile_active()
    if mode == "garbage":
        return respond(200, "not-json {oops")
    if mode == "flap" and _flap_fails():
        return _err(500, "InternalServerError", "simulated flap")

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
    pt = store_kv_get("blobs", ct)
    if pt == None:
        return _err(404, "NotFound", "unknown ciphertext")
    return respond(200, {"plaintext": pt, "plaintextChecksum": "simulated"})

def _flap_fails():
    # persisted in KV so the alternation holds across plugin processes
    return store_kv_incr("kms", "flap") % 2 == 1

def _find_key(key_id):
    for doc in store_collection("keys").list():
        if doc.get("id", "") == key_id:
            return doc
    return None

def _err(status, code, message):
    # OCI SDK error shape: code+message in the body, non-2xx status
    return respond(status, {"code": code, "message": message})
