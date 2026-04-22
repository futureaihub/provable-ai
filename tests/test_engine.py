import os
from app.core.executor import ProtocolExecutor
from app.core.replay import ProtocolReplayer

PROTOCOL_FILE = "test_protocol.yaml"


def setup_module(module):
    with open(PROTOCOL_FILE, "w") as f:
        f.write("""
version: "1.0"
initial_state: submitted
states:
  - submitted
  - review
  - approved
transitions:
  - from_state: submitted
    to_state: review
  - from_state: review
    to_state: approved
""")

    if os.path.exists("protocol_loom.db"):
        os.remove("protocol_loom.db")


def teardown_module(module):
    os.remove(PROTOCOL_FILE)
    if os.path.exists("protocol_loom.db"):
        os.remove("protocol_loom.db")


def test_full_cycle():
    executor = ProtocolExecutor(PROTOCOL_FILE, "instance1")
    executor.execute_transition("review", "alice")
    executor.execute_transition("approved", "bob")

    replayer = ProtocolReplayer(PROTOCOL_FILE, "instance1")
    replayer.verify_and_reconstruct()