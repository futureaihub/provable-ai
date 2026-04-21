"""
provable_ai/signer.py
=====================
"""

import json
import os
import warnings
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

ENV_KEY_VAR = "ZORYNEX_SIGNING_KEY"
DEFAULT_KEY_FILE = "zorynex_signing.key"


class Signer:

    def __init__(self, key_path: str = DEFAULT_KEY_FILE):
        self.key_path = key_path
        self.signing_key = self._load_signing_key()
        self.verify_key = self.signing_key.verify_key

    def _is_temp_path(self, path: str) -> bool:
        return "/tmp/" in path or "pytest" in path or "tmp" in path.lower()

    def _load_signing_key(self) -> SigningKey:
        # Priority 1: env var (production)
        env_hex = os.environ.get(ENV_KEY_VAR, "").strip()
        if env_hex:
            try:
                return SigningKey(env_hex, encoder=HexEncoder)
            except Exception as e:
                raise RuntimeError(
                    f"{ENV_KEY_VAR} is set but invalid: {e}"
                )

        # Priority 2: key file (dev / pilot)
        if os.path.exists(self.key_path):
            with open(self.key_path, "r") as f:
                private_hex = f.read().strip()
            if not private_hex:
                raise RuntimeError(
                    f"Key file '{self.key_path}' is empty. "
                    f"Delete it or set {ENV_KEY_VAR}."
                )
            warnings.warn(
                f"[Zorynex] Loading signing key from file '{self.key_path}'. "
                f"Set {ENV_KEY_VAR} env var for production deployments.",
                UserWarning, stacklevel=3
            )
            return SigningKey(private_hex, encoder=HexEncoder)

        # Priority 3: auto-generate (test / CI)
        new_key = SigningKey.generate()
        if not self._is_temp_path(self.key_path):
            with open(self.key_path, "w") as f:
                f.write(new_key.encode(encoder=HexEncoder).decode())
            warnings.warn(
                f"[Zorynex] Generated new signing key at '{self.key_path}'. "
                f"Back this up immediately or set {ENV_KEY_VAR}. "
                f"Losing this key means existing proofs cannot be re-verified.",
                UserWarning, stacklevel=3
            )
        return new_key

    # ============================================================
    # CANONICAL JSON (STRICT)
    # ============================================================

    def _canonical(self, payload: dict) -> bytes:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

    # ============================================================
    # PUBLIC KEY
    # ============================================================

    def public_key(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode()

    # ============================================================
    # SIGN
    # ============================================================

    def sign(self, payload: dict) -> str:
        if not isinstance(payload, dict):
            raise TypeError("Payload must be a dict")
        return self.signing_key.sign(self._canonical(payload)).signature.hex()

    # ============================================================
    # VERIFY
    # ============================================================

    def verify(self, payload: dict, signature: str) -> bool:
        if not isinstance(payload, dict) or not signature:
            return False
        try:
            self.verify_key.verify(self._canonical(payload), bytes.fromhex(signature))
            return True
        except Exception:
            return False


# ============================================================
# AWS KMS STUB — swap Signer for KMSSigner when ready.
# No interface changes needed in engine.py or anywhere else.
# ============================================================
# import boto3, base64
# class KMSSigner:
#     def __init__(self, key_id=None):
#         self.key_id = key_id or os.environ["ZORYNEX_KMS_KEY_ID"]
#         self.client = boto3.client("kms")
#         self._pub = self.client.get_public_key(KeyId=self.key_id)["PublicKey"]
#     def public_key(self): return base64.b64encode(self._pub).decode()
#     def sign(self, payload):
#         msg = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
#         return base64.b64encode(
#             self.client.sign(KeyId=self.key_id, Message=msg,
#             MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256")["Signature"]
#         ).decode()
#     def verify(self, payload, signature):
#         try:
#             msg = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
#             self.client.verify(KeyId=self.key_id, Message=msg, MessageType="RAW",
#                 Signature=base64.b64decode(signature), SigningAlgorithm="ECDSA_SHA_256")
#             return True
#         except: return False
