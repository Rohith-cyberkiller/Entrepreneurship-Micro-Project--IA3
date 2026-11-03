"""
TrustShield Launcher (Daniel root directory)
Redirects execution to trustshield-member1/app.py
"""

import os
import sys

target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustshield-member1", "app.py")
if os.path.exists(target):
    with open(target, "rb") as f:
        code = compile(f.read(), target, "exec")
        exec(code, {"__name__": "__main__", "__file__": target})
else:
    print(f"Error: Could not locate {target}")
