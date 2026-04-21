
import sys
from tools.verify_core import verify_file


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tools/verify_proof.py proof.json")
        sys.exit(1)

    result = verify_file(sys.argv[1])

    if result.valid:
        print("VERIFIED")
        print(result.reason)
        if result.final_state:
            print(f"Final state: {result.final_state}")
        if result.instance_id:
            print(f"Instance:    {result.instance_id}")
        sys.exit(0)
    else:
        print("FAILED")
        print(result.reason)
        sys.exit(1)
