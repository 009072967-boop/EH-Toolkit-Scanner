import os
import tempfile

# Point the app at a throwaway database/data folder *before* any app module is imported, so
# tests never read or modify the real data/app.db (targets, scan results, audit log).
_tmp = tempfile.mkdtemp(prefix="scanner-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db".replace("\\", "/")
os.environ["AUTH_DOCS_DIR"] = os.path.join(_tmp, "authorizations")
os.environ["UPLOADS_DIR"] = os.path.join(_tmp, "uploads")
os.environ["NVD_API_KEY"] = ""
os.environ["CVE_LOOKUP_ENABLED"] = "false"
