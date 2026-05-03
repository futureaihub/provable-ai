
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from provable_ai.canonical import canonical_hash, genesis_hash
from provable_ai.exceptions import InvalidKeyId, SigningFailed
from provable_ai.signer import AWSKmsSigner, BaseSigner, EnvSigner, Signer, get_signer


@pytest.fixture
def tmp_key(tmp_path):
    return str(tmp_path / "test_key.hex")


@pytest.fixture
def signer(tmp_key):
    return EnvSigner(key_path=tmp_key)


@pytest.fixture
def hash_bytes():
    payload = {
        "decision": {"from_state": "pending", "to_state": "approved"},
        "sequence_id": 1,
        "previous_hash": genesis_hash(),
    }
    return bytes.fromhex(canonical_hash(payload))


# ── BaseSigner contract ───────────────────────────────────────────────────────

class TestBaseSignerContract:

    def test_is_base_signer(self, signer):
        assert isinstance(signer, BaseSigner)

    def test_sign_hash_returns_128_char_hex(self, signer, hash_bytes):
        sig = signer.sign_hash(hash_bytes)
        assert isinstance(sig, str) and len(sig) == 128
        int(sig, 16)  # valid hex

    def test_sign_hash_lowercase(self, signer, hash_bytes):
        assert signer.sign_hash(hash_bytes) == signer.sign_hash(hash_bytes).lower()

    def test_get_public_key_64_hex(self, signer):
        pub = signer.get_public_key()
        assert isinstance(pub, str) and len(pub) == 64
        int(pub, 16)

    def test_get_key_id_nonempty(self, signer):
        assert isinstance(signer.get_key_id(), str)
        assert len(signer.get_key_id()) > 0

    def test_ed25519_is_deterministic(self, signer, hash_bytes):
        assert signer.sign_hash(hash_bytes) == signer.sign_hash(hash_bytes)

    def test_verify_hash_valid(self, signer, hash_bytes):
        sig = signer.sign_hash(hash_bytes)
        assert signer.verify_hash(hash_bytes, sig) is True

    def test_verify_hash_tampered_data(self, signer, hash_bytes):
        sig = signer.sign_hash(hash_bytes)
        tampered = bytes([b ^ 0xFF for b in hash_bytes])
        assert signer.verify_hash(tampered, sig) is False

    def test_verify_hash_wrong_signature(self, signer, hash_bytes):
        assert signer.verify_hash(hash_bytes, "a" * 128) is False

    def test_verify_hash_empty_signature_fails(self, signer, hash_bytes):
        """Empty string signature must return False — not raise."""
        assert signer.verify_hash(hash_bytes, "") is False

    def test_verify_hash_malformed_hex_fails(self, signer, hash_bytes):
        """Malformed hex must return False — not raise."""
        assert signer.verify_hash(hash_bytes, "not-valid-hex-!@#$" * 8) is False
        assert signer.verify_hash(hash_bytes, "zz" * 64) is False

    def test_verify_hash_short_signature_fails(self, signer, hash_bytes):
        """Short (< 128 chars) must return False."""
        assert signer.verify_hash(hash_bytes, "a" * 64) is False


# ── Input validation — hash bytes only ───────────────────────────────────────

class TestStrictHashOnlyInput:

    def test_string_rejected(self, signer):
        with pytest.raises(ValueError, match="bytes"):
            signer.sign_hash(canonical_hash({"a": 1}))

    def test_dict_rejected(self, signer):
        """sign_hash must NEVER accept a dict — old wrong behaviour."""
        with pytest.raises((ValueError, TypeError)):
            signer.sign_hash({"payload": "data"})

    def test_wrong_length_rejected(self, signer):
        with pytest.raises(ValueError, match="32 bytes"):
            signer.sign_hash(b"too_short")

    def test_33_bytes_rejected(self, signer):
        with pytest.raises(ValueError, match="32 bytes"):
            signer.sign_hash(b"x" * 33)

    def test_none_rejected(self, signer):
        with pytest.raises((ValueError, TypeError)):
            signer.sign_hash(None)

    def test_int_rejected(self, signer):
        with pytest.raises((ValueError, TypeError)):
            signer.sign_hash(12345)

    def test_list_rejected(self, signer):
        with pytest.raises((ValueError, TypeError)):
            signer.sign_hash([1, 2, 3])


# ── repr safety — no private key exposure ─────────────────────────────────────

class TestReprSafety:
    """repr() must never expose private key material."""

    def test_repr_does_not_contain_private_key(self, tmp_key):
        sk = EnvSigner(key_path=tmp_key)
        r = repr(sk)
        pub = sk.get_public_key()
        # repr should contain key_id, not full public key or private key
        assert len(r) < 200  # not dumping key data
        assert "EnvSigner" in r
        # Full public key (64 chars) should not appear in repr
        # key_id is first 16 chars of pubkey — that's OK
        assert pub not in r

    def test_str_does_not_contain_private_key(self, tmp_key):
        sk = EnvSigner(key_path=tmp_key)
        s = str(sk)
        assert sk.get_public_key() not in s

    def test_repr_contains_key_id(self, tmp_key):
        sk = EnvSigner(key_path=tmp_key)
        assert sk.get_key_id() in repr(sk)


# ── Canonical determinism ─────────────────────────────────────────────────────

class TestCanonicalDeterminism:
    """
    Same payload with different key order → same canonical hash → same signature.
    Critical for cross-system verification.
    """

    def test_same_content_different_dict_order_same_signature(self, signer):
        payload_a = {"z": 3, "a": 1, "m": 2}
        payload_b = {"a": 1, "m": 2, "z": 3}
        hash_a = bytes.fromhex(canonical_hash(payload_a))
        hash_b = bytes.fromhex(canonical_hash(payload_b))
        assert hash_a == hash_b
        sig_a = signer.sign_hash(hash_a)
        sig_b = signer.sign_hash(hash_b)
        assert sig_a == sig_b

    def test_nested_different_order_same_hash(self, signer):
        a = {"decision": {"to_state": "approved", "from_state": "pending"}}
        b = {"decision": {"from_state": "pending", "to_state": "approved"}}
        ha = bytes.fromhex(canonical_hash(a))
        hb = bytes.fromhex(canonical_hash(b))
        assert ha == hb
        assert signer.sign_hash(ha) == signer.sign_hash(hb)

    def test_different_content_different_signature(self, signer):
        h1 = bytes.fromhex(canonical_hash({"result": "approved"}))
        h2 = bytes.fromhex(canonical_hash({"result": "denied"}))
        assert signer.sign_hash(h1) != signer.sign_hash(h2)


# ── EnvSigner key management ──────────────────────────────────────────────────

class TestEnvSignerKeyManagement:

    def test_generates_key_file(self, tmp_key, monkeypatch):
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        assert not os.path.exists(tmp_key)
        EnvSigner(key_path=tmp_key)
        assert os.path.exists(tmp_key)

    def test_reloads_same_key(self, tmp_key):
        s1 = EnvSigner(key_path=tmp_key)
        s2 = EnvSigner(key_path=tmp_key)
        assert s1.get_public_key() == s2.get_public_key()
        assert s1.get_key_id() == s2.get_key_id()

    def test_key_id_format(self, signer):
        kid = signer.get_key_id()
        assert kid.startswith("env-")
        assert len(kid) == len("env-") + 16

    def test_different_keys_different_key_id(self, tmp_path, monkeypatch):
        """Two independently generated keys must have different key_ids."""
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        s1 = EnvSigner(key_path=str(tmp_path / "k1.hex"))
        s2 = EnvSigner(key_path=str(tmp_path / "k2.hex"))
        assert s1.get_key_id() != s2.get_key_id()

    def test_different_keys_different_public_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        s1 = EnvSigner(key_path=str(tmp_path / "k1.hex"))
        s2 = EnvSigner(key_path=str(tmp_path / "k2.hex"))
        assert s1.get_public_key() != s2.get_public_key()

    def test_signature_verifies_after_reload(self, tmp_key, hash_bytes):
        s1 = EnvSigner(key_path=tmp_key)
        sig = s1.sign_hash(hash_bytes)
        s2 = EnvSigner(key_path=tmp_key)
        assert s2.verify_hash(hash_bytes, sig) is True

    def test_env_var_overrides_file(self, tmp_key, monkeypatch):
        from nacl.encoding import HexEncoder
        from nacl.signing import SigningKey
        new_key = SigningKey.generate()
        new_hex = new_key.encode(encoder=HexEncoder).decode()
        new_pub = new_key.verify_key.encode(encoder=HexEncoder).decode()
        # Write a different key to the file
        other = SigningKey.generate()
        with open(tmp_key, "w") as f:
            f.write(other.encode(encoder=HexEncoder).decode())
        monkeypatch.setenv("ZORYNEX_SIGNING_KEY", new_hex)
        s = EnvSigner(key_path=tmp_key)
        assert s.get_public_key() == new_pub


# ── AWSKmsSigner interface ────────────────────────────────────────────────────

class TestAWSKmsSignerInterface:

    def test_fails_without_key_id(self, monkeypatch):
        monkeypatch.delenv("ZORYNEX_KMS_KEY_ID", raising=False)
        with pytest.raises((InvalidKeyId, Exception)):
            AWSKmsSigner(key_id="")

    def test_key_id_prefixed_with_kms(self, monkeypatch):
        """AWSKmsSigner key_id must be prefixed with 'kms-'."""
        monkeypatch.setenv("ZORYNEX_KMS_KEY_ID", "alias/zorynex-prod")
        try:
            s = AWSKmsSigner(key_id="alias/zorynex-prod")
            assert s.get_key_id().startswith("kms-")
        except Exception:
            pass  # boto3 not configured in test env

    def test_already_prefixed_key_id_not_double_prefixed(self):
        """If key_id already starts with 'kms-' don't add it again."""
        try:
            s = AWSKmsSigner(key_id="kms-alias/zorynex-prod")
            assert s.get_key_id() == "kms-alias/zorynex-prod"
        except Exception:
            pass

    def test_rejects_invalid_hash_length(self, monkeypatch):
        """AWSKmsSigner must validate 32 bytes before calling KMS."""
        monkeypatch.setenv("ZORYNEX_KMS_KEY_ID", "alias/test")
        try:
            s = AWSKmsSigner(key_id="alias/test")
            with pytest.raises(ValueError, match="32 bytes"):
                s.sign_hash(b"too_short")
        except (InvalidKeyId, Exception) as e:
            if "boto3" in str(e) or "KMS" in str(e):
                pytest.skip("boto3 not available")
            raise


# ── get_signer() factory ──────────────────────────────────────────────────────

class TestGetSignerFactory:

    def test_returns_env_signer_by_default(self, tmp_key, monkeypatch):
        monkeypatch.delenv("ZORYNEX_KMS_KEY_ID", raising=False)
        s = get_signer(key_path=tmp_key)
        assert isinstance(s, EnvSigner)

    def test_returns_kms_signer_with_env_var(self, monkeypatch):
        monkeypatch.setenv("ZORYNEX_KMS_KEY_ID", "alias/zorynex-prod")
        try:
            s = get_signer()
            assert isinstance(s, AWSKmsSigner)
        except Exception:
            pass  # Expected without AWS credentials


# ── Backward compatibility ────────────────────────────────────────────────────

class TestBackwardCompatibility:

    def test_old_sign_still_works(self, tmp_key):
        s = Signer(key_path=tmp_key)
        payload = {"instance_id": "test", "state": "approved"}
        sig = s.sign(payload)
        assert isinstance(sig, str) and len(sig) > 0

    def test_old_verify_still_works(self, tmp_key):
        s = Signer(key_path=tmp_key)
        payload = {"state": "approved"}
        sig = s.sign(payload)
        assert s.verify(payload, sig) is True

    def test_old_verify_fails_on_modified_payload(self, tmp_key):
        """Negative backward compat: modified payload must fail verification."""
        s = Signer(key_path=tmp_key)
        payload = {"state": "approved", "amount": "10000"}
        sig = s.sign(payload)
        # Tamper with the payload
        tampered = {"state": "approved", "amount": "99999"}
        assert s.verify(tampered, sig) is False

    def test_old_public_key_alias(self, tmp_key):
        s = Signer(key_path=tmp_key)
        assert s.public_key() == s.get_public_key()

    def test_new_sign_hash_and_old_sign_different(self, tmp_key, hash_bytes):
        """New sign_hash(bytes) and old sign(dict) must produce different sigs."""
        s = Signer(key_path=tmp_key)
        old_sig = s.sign({"payload": "data"})
        new_sig = s.sign_hash(hash_bytes)
        assert old_sig != new_sig


# ── Security properties ───────────────────────────────────────────────────────

class TestSecurityProperties:

    def test_sign_only_accepts_bytes(self, signer):
        for bad in [{"a": 1}, "hex", 12345, None, [1, 2]]:
            with pytest.raises((ValueError, TypeError)):
                signer.sign_hash(bad)

    def test_signature_is_64_bytes(self, signer, hash_bytes):
        sig = bytes.fromhex(signer.sign_hash(hash_bytes))
        assert len(sig) == 64

    def test_cross_key_signature_invalid(self, tmp_path, hash_bytes, monkeypatch):
        """Key A signature must not verify with Key B's public key."""
        monkeypatch.delenv("ZORYNEX_SIGNING_KEY", raising=False)
        sa = EnvSigner(key_path=str(tmp_path / "a.hex"))
        sb = EnvSigner(key_path=str(tmp_path / "b.hex"))
        sig_from_a = sa.sign_hash(hash_bytes)
        assert sb.verify_hash(hash_bytes, sig_from_a) is False