import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for path in (ROOT, os.path.join(ROOT, "monitor"), os.path.join(ROOT, "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture(autouse=True)
def isolate_from_ci_environment(monkeypatch):
    """Keep tests from writing into the real GitHub Actions job summary or using CI credentials.

    Tests that need one of these variables set it themselves with monkeypatch.setenv.
    """
    for name in ("GITHUB_STEP_SUMMARY", "GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
                 "SONAR_TOKEN", "NVIDIA_API_KEY", "ALERT_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
