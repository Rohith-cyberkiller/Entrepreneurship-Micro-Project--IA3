"""
TrustShield Member 2 CLI Predictor Launcher (Jerom root directory)
Redirects execution to trustshield-member2/cli_predict.py
"""

import os
import sys

target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustshield-member2", "cli_predict.py")
if os.path.exists(target):
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustshield-member2"))
    with open(target, "rb") as f:
        code = compile(f.read(), target, "exec")
        exec(code, {"__name__": "__main__", "__file__": target})
else:
    print(f"Error: Could not locate {target}")
