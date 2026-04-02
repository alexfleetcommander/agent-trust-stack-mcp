"""RFC 3161 TSA helpers for Chain of Consciousness anchoring.

Builds DER-encoded TimeStampReq messages and parses TimeStampResp status.
No external dependencies — pure Python DER encoding.
"""

import secrets


def _der_tag_length(tag: int, content: bytes) -> bytes:
    """Wrap content bytes with a DER tag-length header."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + content
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + content


def build_rfc3161_tsq(hash_bytes: bytes) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq for a SHA-256 digest.

    Structure per RFC 3161 Section 2.4.1:
      TimeStampReq ::= SEQUENCE {
          version INTEGER {v1(1)}, messageImprint MessageImprint,
          nonce INTEGER OPTIONAL, certReq BOOLEAN DEFAULT FALSE }
    """
    # SHA-256 OID: 2.16.840.1.101.3.4.2.1
    sha256_oid = _der_tag_length(0x06, bytes([
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
    ]))
    alg_id = _der_tag_length(0x30, sha256_oid + bytes([0x05, 0x00]))  # SEQUENCE { OID, NULL }
    msg_imprint = _der_tag_length(0x30, alg_id + _der_tag_length(0x04, hash_bytes))

    version = _der_tag_length(0x02, bytes([0x01]))  # INTEGER v1

    # Random nonce for replay protection (positive integer)
    nonce_raw = secrets.token_bytes(8)
    if nonce_raw[0] & 0x80:
        nonce_raw = b"\x00" + nonce_raw
    nonce = _der_tag_length(0x02, nonce_raw)

    cert_req = _der_tag_length(0x01, bytes([0xFF]))  # BOOLEAN TRUE

    return _der_tag_length(0x30, version + msg_imprint + nonce + cert_req)


def parse_tsr_status(tsr_bytes: bytes) -> dict:
    """Parse an RFC 3161 TimeStampResp to extract status info.

    Returns dict with status code, text, token presence, and size.
    For full cryptographic verification use: openssl ts -verify
    """
    STATUS_NAMES = {
        0: "granted",
        1: "grantedWithMods",
        2: "rejection",
        3: "waiting",
        4: "revocationWarning",
        5: "revocationNotification",
    }

    def read_tl(data: bytes, off: int) -> tuple:
        tag = data[off]
        off += 1
        lb = data[off]
        off += 1
        if lb < 0x80:
            return tag, lb, off
        n = lb & 0x7F
        length = 0
        for _ in range(n):
            length = (length << 8) | data[off]
            off += 1
        return tag, length, off

    try:
        _, outer_len, outer_start = read_tl(tsr_bytes, 0)
        outer_end = outer_start + outer_len

        _, si_len, si_start = read_tl(tsr_bytes, outer_start)
        si_end = si_start + si_len

        tag, int_len, int_start = read_tl(tsr_bytes, si_start)
        if tag != 0x02:
            return {
                "status": -1,
                "status_text": "parse_error: expected INTEGER",
                "has_token": False,
                "tsr_size": len(tsr_bytes),
            }
        status_val = int.from_bytes(
            tsr_bytes[int_start : int_start + int_len], "big", signed=True
        )

        return {
            "status": status_val,
            "status_text": STATUS_NAMES.get(status_val, f"unknown({status_val})"),
            "has_token": si_end < outer_end,
            "tsr_size": len(tsr_bytes),
        }
    except (IndexError, ValueError) as e:
        return {
            "status": -1,
            "status_text": f"parse_error: {e}",
            "has_token": False,
            "tsr_size": len(tsr_bytes),
        }
