"""
ThreatFuse Member 3 CLI Launcher (Krishanth root directory)
Redirects execution to threatfuse-member3/cli_decision.py
"""

import os
import sys

target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatfuse-member3", "cli_decision.py")
if os.path.exists(target):
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatfuse-member3"))
    with open(target, "rb") as f:
        code = compile(f.read(), target, "exec")
        exec(code, {"__name__": "__main__", "__file__": target})
else:
    print(f"Error: Could not locate {target}")
