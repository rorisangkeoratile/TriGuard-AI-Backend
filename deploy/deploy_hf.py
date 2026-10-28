"""Deploy the backend to a Hugging Face Space (Docker).

    .venv\\Scripts\\python.exe deploy\\deploy_hf.py

Reads from .env (never uploaded): HF_TOKEN (a "write" token), optional HF_SPACE (default triguard-ai),
GEMINI_API_KEY, DEPLOY_DATABASE_URL (the hosted Postgres; named so the local server keeps using SQLite),
FRONTEND_URL and REPORTER_HASH_SECRET (created and saved to .env if missing).
Secrets are stored as private Space secrets; values are never printed.
"""

import fnmatch
import secrets
import sys
from pathlib import Path

from huggingface_hub import CommitOperationAdd, HfApi

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
# Never uploaded: secrets, local data and models, caches.
IGNORE = [".env", ".env.*", ".venv/*", "data/*", "models/*", ".git/*", ".pytest_cache/*", "*/__pycache__/*",
          "*.pyc", "*.db", "README.md"]
FRONT_MATTER = """---
title: TriGuard AI
emoji: 🛡️
colorFrom: purple
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
short_description: AI voice-clone and scam checks for South Africa
---

"""


def read_env() -> dict[str, str]:
    values = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def ignored(rel: str) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel.split("/")[-1], p) for p in IGNORE) \
        or rel.startswith((".venv/", "data/", "models/", ".git/", ".pytest_cache/"))


def main() -> None:
    env = read_env()
    token = env.get("HF_TOKEN")
    if not token:
        sys.exit("Add HF_TOKEN=<your Hugging Face write token> to .env first.")
    if not env.get("REPORTER_HASH_SECRET"):
        # Keep the same secret across deploys, or duplicate-report checks reset.
        env["REPORTER_HASH_SECRET"] = secrets.token_hex(32)
        with ENV_FILE.open("a", encoding="utf-8") as f:
            f.write(f"\nREPORTER_HASH_SECRET={env['REPORTER_HASH_SECRET']}\n")

    env["DATABASE_URL"] = env.get("DEPLOY_DATABASE_URL") or env.get("DATABASE_URL", "")

    api = HfApi(token=token)
    owner = api.whoami()["name"]
    repo_id = f"{owner}/{env.get('HF_SPACE', 'triguard-ai')}"
    api.create_repo(repo_id, repo_type="space", space_sdk="docker", exist_ok=True)
    host = f"https://{repo_id.replace('/', '-').replace('_', '-').replace('.', '-').lower()}.hf.space"

    for key in ("GEMINI_API_KEY", "DATABASE_URL", "REPORTER_HASH_SECRET"):
        if env.get(key):
            api.add_space_secret(repo_id, key, env[key])
            print(f"secret set: {key}")
        else:
            print(f"secret missing (skipped): {key}")
    origins = ",".join(filter(None, [env.get("FRONTEND_URL", "").rstrip("/"), "http://localhost:5173",
                                     "http://127.0.0.1:5173"]))
    for key, value in {"ENVIRONMENT": "production", "CORS_ORIGINS": origins, "CORS_ORIGIN_REGEX": ""}.items():
        api.add_space_variable(repo_id, key, value)

    ops = []
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT).as_posix()
        if path.is_file() and not ignored(rel):
            ops.append(CommitOperationAdd(rel, str(path)))
    readme = FRONT_MATTER + (ROOT / "README.md").read_text(encoding="utf-8")
    ops.append(CommitOperationAdd("README.md", readme.encode("utf-8")))
    # Outlook add-in manifest pointing at the Space instead of https://localhost:3000.
    manifest = (ROOT / "outlook-addin" / "manifest.xml").read_text(encoding="utf-8")
    live = manifest.replace("https://localhost:3000", host)
    (ROOT / "outlook-addin" / "manifest-live.xml").write_text(live, encoding="utf-8")
    ops.append(CommitOperationAdd("outlook-addin/manifest-live.xml", live.encode("utf-8")))

    uploaded = {op.path_in_repo for op in ops}
    assert not any(p == ".env" or p.startswith((".venv/", "data/", "models/")) for p in uploaded)
    api.create_commit(repo_id, repo_type="space", operations=ops, commit_message="Deploy TriGuard AI backend")
    print(f"uploaded {len(ops)} files to https://huggingface.co/spaces/{repo_id}")
    print(f"API (live after the build, ~10 min): {host}")


if __name__ == "__main__":
    main()
