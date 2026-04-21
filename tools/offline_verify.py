
import sys
from tools.verify_core import verify_file


def verify_proof(path: str):
    
    result = verify_file(path)
    return result.valid, result.reason, result.final_state


# ============================================================
# CLI ENTRY
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python offline_verify.py proof.json")
        sys.exit(1)

    result = verify_file(sys.argv[1])

    if result.valid:
        print(f"VALID: {result.reason}")
        if result.final_state:
            print(f"Final state: {result.final_state}")
        if result.instance_id:
            print(f"Instance:    {result.instance_id}")
        sys.exit(0)
    else:
        print(f"INVALID: {result.reason}")
        sys.exit(1)
