"""
CertiScan Studio // MalDetect-AI Root Runner
Redirects to the certiscan-maldetect-ai full application.
"""

import os
import sys

TARGET_APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certiscan-maldetect-ai", "app.py")

if __name__ == "__main__":
    import streamlit.web.bootstrap as bootstrap
    from streamlit import config as _config

    _config.set_option("server.headless", True)
    sys.argv = ["streamlit", "run", TARGET_APP]
    sys.exit(bootstrap.run(TARGET_APP, False, [], flag_options={}))
