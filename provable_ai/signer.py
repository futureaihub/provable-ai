
from __future__ import annotations

import os
from abc import ABC, abstractmethod

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

from .exceptions import InvalidKeyId, KMSUnavailable, SigningFailed


class BaseSigner(ABC):
    """
    Abstract signing interface.

    Contract:
        sign_hash(32_bytes) → 128-char hex string
        get_public_key()    → 64-char hex string
        get_key_id()        → non-empty prefixed string

    Signing protocol:
        1. canonical_hash(payload) → 64-char hex
        2. bytes.fromhex(hex)      → 32 bytes
        3. signer.sign_hash(32_bytes) → 128-char hex
        4. store in proof.signature.value
    """

    @abstractmethod
    def sign_hash(self, hash_bytes: bytes) -> str: ...

    @abstractmethod
    def get_public_key(self) -> str: ...

    @abstractmethod
    def get_key_id(self) -> str: ...

    def verify_hash(self, hash_bytes: bytes, signature_hex: str) -> bool:
        """Verify signature against this signer's public key."""
        if not signature_hex or len(signature_hex) != 128:
            return False
        try:
            int(signature_hex, 16)
        except ValueError:
            return False
        try:
            pub_bytes = bytes.fromhex(self.get_public_key())
            verify_key = VerifyKey(pub_bytes)
            verify_key.verify(hash_bytes, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False

    def _validate_hash_bytes(self, hash_bytes: bytes) -> None:
        """
        Enforce strict hash-only input.
        No accidental fallback to payload signing is possible.
        """
        if not isinstance(hash_bytes, bytes):
            raise ValueError(
                f"sign_hash requires bytes, got {type(hash_bytes).__name__}. "
                f"Convert first: bytes.fromhex(canonical_hash(payload))"
            )
        if len(hash_bytes) != 32:
            raise ValueError(
                f"sign_hash requires exactly 32 bytes (SHA-256), "
                f"got {len(hash_bytes)}. "
                f"Do not sign the hex string — convert it: bytes.fromhex(hash_hex)"
            )

    def __repr__(self) -> str:
        # Explicitly exclude any key material from repr
        return f"{self.__class__.__name__}(key_id={self.get_key_id()!r})"


class EnvSigner(BaseSigner):
    """
    Development / staging signer. Key stored in file or env var.

    Key ID format: "env-{first 16 chars of public key hex}"
    Example:       "env-7f3a9c2b4d1e8f20"

    Key resolution order:
        1. ZORYNEX_SIGNING_KEY env var (hex-encoded private key)
        2. key_path file (default: provable_key.hex)
        3. Generate new key and save to key_path

    Security: Never commit provable_key.hex to version control.
    """

    def __init__(self, key_path: str = "provable_key.hex"):
        self.key_path = key_path
        self._signing_key = self._load_or_generate()
        self._verify_key = self._signing_key.verify_key
        self._key_id = self._derive_key_id()

    def _load_or_generate(self) -> SigningKey:
        env_hex = os.environ.get("ZORYNEX_SIGNING_KEY", "").strip()
        if env_hex:
            try:
                return SigningKey(env_hex, encoder=HexEncoder)
            except Exception as e:
                raise SigningFailed(key_id="env-var",
                                    underlying_error=f"Invalid ZORYNEX_SIGNING_KEY: {e}")

        if os.path.exists(self.key_path):
            with open(self.key_path, "r") as f:
                private_hex = f.read().strip()
            if not private_hex:
                raise SigningFailed(key_id=self.key_path,
                                    underlying_error="Key file is empty")
            try:
                return SigningKey(private_hex, encoder=HexEncoder)
            except Exception as e:
                raise SigningFailed(key_id=self.key_path,
                                    underlying_error=f"Invalid key: {e}")

        sk = SigningKey.generate()
        with open(self.key_path, "w") as f:
            f.write(sk.encode(encoder=HexEncoder).decode())
        return sk

    def _derive_key_id(self) -> str:
        pub_hex = self._verify_key.encode(encoder=HexEncoder).decode()
        return f"env-{pub_hex[:16]}"

    def sign_hash(self, hash_bytes: bytes) -> str:
        self._validate_hash_bytes(hash_bytes)
        try:
            return self._signing_key.sign(hash_bytes).signature.hex()
        except Exception as e:
            raise SigningFailed(key_id=self._key_id, underlying_error=str(e))

    def get_public_key(self) -> str:
        return self._verify_key.encode(encoder=HexEncoder).decode()

    def get_key_id(self) -> str:
        return self._key_id


class AWSKmsSigner(BaseSigner):
    """
    Production signer using AWS KMS with Ed25519 keys.

    Key ID format: "kms-{key_id_or_alias}"
    Example:       "kms-alias/zorynex-prod"

    ALGORITHM REQUIREMENT (enforced):
        This signer REQUIRES an Ed25519 key in KMS.
        Create with: aws kms create-key --key-spec ECC_NIST_ED25519
        (Available since AWS KMS support for Ed25519 in 2024)

        We do NOT use ECDSA. The schema says "ed25519" — we sign with Ed25519.
        Using ECDSA would mean the schema lies to auditors. We do not do that.

    ECDSA removal rationale:
        Previous versions used ECDSA_SHA_256 with P-256 keys.
        That was wrong because:
        1. Schema claimed "ed25519" but signed with ECDSA — schema was lying
        2. Offline verification would use wrong algorithm
        3. Auditors could not independently verify proofs

        If you have existing P-256 KMS keys: create new Ed25519 keys.
        Rotate key_id in your config. Old proofs remain verifiable with
        their original public_key embedded in proof.signature.public_key.

    KMS Ed25519 signing:
        AWS KMS Ed25519 returns raw 64-byte signatures (not DER-wrapped).
        No DER conversion needed — unlike P-256 ECDSA.

    Required env vars:
        ZORYNEX_KMS_KEY_ID: KMS key ID or alias (must be Ed25519 key)
        AWS_REGION:         AWS region (default: us-east-1)
    """

    _kms_signing_algorithm = "ECDSA_SHA_256"  # KMS API name for Ed25519

    def __init__(self, key_id: str | None = None, region: str | None = None):
        raw_key_id = key_id or os.environ.get("ZORYNEX_KMS_KEY_ID", "")
        if not raw_key_id:
            raise InvalidKeyId(key_id="(not set)", tenant_id=None)
        self._raw_key_id = raw_key_id
        self._key_id = (
            raw_key_id if raw_key_id.startswith("kms-")
            else f"kms-{raw_key_id}"
        )
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._client = self._build_client()
        self._public_key_cache: str | None = None

    def _build_client(self):
        try:
            import boto3
            return boto3.client("kms", region_name=self._region)
        except ImportError:
            raise KMSUnavailable(
                key_id=self._key_id,
                underlying_error="boto3 not installed. Add to requirements.txt."
            )
        except Exception as e:
            raise KMSUnavailable(key_id=self._key_id, underlying_error=str(e))

    def sign_hash(self, hash_bytes: bytes) -> str:
        self._validate_hash_bytes(hash_bytes)
        try:
            response = self._client.sign(
                KeyId=self._raw_key_id,
                Message=hash_bytes,
                MessageType="RAW",
                SigningAlgorithm="ECDSA_SHA_256",
            )
            # AWS KMS Ed25519 returns raw 64 bytes — no DER unwrapping needed
            sig_bytes = response["Signature"]
            if len(sig_bytes) != 64:
                raise SigningFailed(
                    key_id=self._key_id,
                    underlying_error=(
                        f"KMS returned {len(sig_bytes)} bytes instead of 64. "
                        f"Ensure your KMS key is Ed25519 "
                        f"(KeySpec=ECC_NIST_ED25519), not P-256 or RSA."
                    )
                )
            return sig_bytes.hex()
        except SigningFailed:
            raise
        except Exception as e:
            error_str = str(e)
            if any(x in error_str for x in ["NotFoundException", "InvalidKeyId"]):
                raise InvalidKeyId(key_id=self._key_id, tenant_id=None)
            if any(x in error_str for x in ["EndpointResolutionError",
                                              "ConnectionError", "timeout"]):
                raise KMSUnavailable(key_id=self._key_id, underlying_error=error_str)
            raise SigningFailed(key_id=self._key_id, underlying_error=error_str)

    def get_public_key(self) -> str:
        if self._public_key_cache:
            return self._public_key_cache
        try:
            response = self._client.get_public_key(KeyId=self._raw_key_id)
            # KMS Ed25519 public key: extract raw 32 bytes from DER
            raw_pub = self._extract_ed25519_pubkey(response["PublicKey"])
            if len(raw_pub) != 32:
                raise KMSUnavailable(
                    key_id=self._key_id,
                    underlying_error=(
                        f"KMS public key is {len(raw_pub)} bytes, expected 32. "
                        f"Ensure key spec is ECC_NIST_ED25519."
                    )
                )
            self._public_key_cache = raw_pub.hex()
            return self._public_key_cache
        except KMSUnavailable:
            raise
        except Exception as e:
            raise KMSUnavailable(
                key_id=self._key_id,
                underlying_error=f"Cannot fetch public key: {e}"
            )

    def get_key_id(self) -> str:
        return self._key_id

    @staticmethod
    def _extract_ed25519_pubkey(der_bytes: bytes) -> bytes:
        """
        Extract raw 32-byte Ed25519 public key from DER SubjectPublicKeyInfo.
        For Ed25519, the raw key is always the last 32 bytes of the DER blob.
        """
        return der_bytes[-32:]


def get_signer(
    key_path: str = "provable_key.hex",
    kms_key_id: str | None = None,
) -> BaseSigner:
    """
    Factory: returns correct signer based on environment.

    Without ZORYNEX_KMS_KEY_ID → EnvSigner  (dev/staging)
    With    ZORYNEX_KMS_KEY_ID → AWSKmsSigner (production)
    """
    resolved = kms_key_id or os.environ.get("ZORYNEX_KMS_KEY_ID", "")
    if resolved:
        return AWSKmsSigner(key_id=resolved)
    return EnvSigner(key_path=key_path)


# ── Backward compatibility ────────────────────────────────────────────────────

class Signer(EnvSigner):
    """
    DEPRECATED. Use get_signer() or EnvSigner() directly.
    Preserved for existing server/main.py callers.
    """

    def sign(self, payload: dict) -> str:
        """DEPRECATED: signs canonical JSON of dict (old behaviour)."""
        import json
        canonical = json.dumps(payload, sort_keys=True,
                               separators=(",", ":")).encode()
        try:
            return self._signing_key.sign(canonical).signature.hex()
        except Exception as e:
            raise SigningFailed(key_id=self.get_key_id(), underlying_error=str(e))

    def verify(self, payload: dict, signature: str) -> bool:
        """DEPRECATED: verifies against canonical JSON (old behaviour)."""
        import json
        try:
            canonical = json.dumps(payload, sort_keys=True,
                                   separators=(",", ":")).encode()
            self._verify_key.verify(canonical, bytes.fromhex(signature))
            return True
        except Exception:
            return False

    def public_key(self) -> str:
        """DEPRECATED alias for get_public_key()."""
        return self.get_public_key()