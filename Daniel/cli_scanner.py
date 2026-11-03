"""
TrustShield CLI Scanner Launcher (Daniel root directory)
Redirects execution to trustshield-member1/cli_scanner.py
"""

import os
import sys

target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustshield-member1", "cli_scanner.py")
if os.path.exists(target):
    # Change working directory so relative demo_samples paths resolve cleanly
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustshield-member1"))
    with open(target, "rb") as f:
        code = compile(f.read(), target, "exec")
        exec(code, {"__name__": "__main__", "__file__": target})
else:
    print(f"Error: Could not locate {target}")
