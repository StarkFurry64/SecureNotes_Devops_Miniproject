import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for path in (ROOT, os.path.join(ROOT, "monitor"), os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)
