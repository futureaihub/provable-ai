import json
import os
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder


class Signer:
    """
    ED25519 signing layer.
    Generates keypair on first run.
    Public key can be shared externally.
    """

    def __init__(self, key_path="provable_key.hex"):

        self.key_path = key_path

        if os.path.exists(self.key_path):
            with open(self.key_path, "r") as f:
                private_hex = f.read().strip()

            if not private_hex:
                raise Exception("Private key file is empty.")

            self.signing_key = SigningKey(private_hex, encoder=HexEncoder)

        else:
            self.signing_key = SigningKey.generate()

            with open(self.key_path, "w") as f:
                f.write(
                    self.signing_key.encode(encoder=HexEncoder).decode()
                )

        self.verify_key = self.signing_key.verify_key

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
            raise Exception("Payload must be dict")

        canonical_bytes = self._canonical(payload)

        signature = self.signing_key.sign(
            canonical_bytes
        ).signature

        return signature.hex()

    # ============================================================
    # VERIFY
    # ============================================================

    def verify(self, payload: dict, signature: str) -> bool:

        if not isinstance(payload, dict):
            return False

        if not signature:
            return False

        try:
            canonical_bytes = self._canonical(payload)

            self.verify_key.verify(
                canonical_bytes,
                bytes.fromhex(signature)
            )

            return True

        except Exception:
            return False