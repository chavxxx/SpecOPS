"""
System In-App GitHub Updater Service for SpecOPS
Connects directly to chavxxx/SpecOPS to check for new releases and updates.
"""
import os
import subprocess
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import httpx

logger = logging.getLogger("wispnet.updater")

CURRENT_VERSION = "v1.2.0"
REPO_OWNER = "chavxxx"
REPO_NAME = "SpecOPS"
GITHUB_API_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"

class SystemUpdater:
    def __init__(self, repo_dir: Optional[str] = None):
        self.repo_dir = repo_dir or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.token = os.getenv("GITHUB_TOKEN", "").strip()

    def get_current_commit(self) -> Dict[str, str]:
        """Gets current git commit hash and date"""
        try:
            cmd = ["git", "rev-parse", "HEAD"]
            commit = subprocess.check_output(cmd, cwd=self.repo_dir, text=True, stderr=subprocess.DEVNULL).strip()
            short_commit = commit[:7] if commit else "unknown"

            cmd_date = ["git", "log", "-1", "--format=%cd", "--date=iso-strict"]
            commit_date = subprocess.check_output(cmd_date, cwd=self.repo_dir, text=True, stderr=subprocess.DEVNULL).strip()

            cmd_msg = ["git", "log", "-1", "--format=%s"]
            commit_msg = subprocess.check_output(cmd_msg, cwd=self.repo_dir, text=True, stderr=subprocess.DEVNULL).strip()

            return {
                "commit": commit,
                "short_commit": short_commit,
                "date": commit_date,
                "message": commit_msg
            }
        except Exception as e:
            logger.warning(f"Failed to read local git commit: {e}")
            return {
                "commit": "unknown",
                "short_commit": "v1.2.0",
                "date": datetime.now(timezone.utc).isoformat(),
                "message": "Production Release"
            }

    def check_for_updates(self, token: Optional[str] = None) -> Dict[str, Any]:
        """
        Queries GitHub to inspect latest commit on main branch.
        Uses git ls-remote or GitHub REST API.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        current = self.get_current_commit()
        auth_token = token or self.token

        remote_commit = None
        commit_message = None
        commit_date = None

        # 1. First attempt: git ls-remote (fastest if git SSH/credentials configured)
        try:
            cmd = ["git", "ls-remote", "origin", "refs/heads/main"]
            out = subprocess.check_output(cmd, cwd=self.repo_dir, text=True, stderr=subprocess.DEVNULL, timeout=6.0).strip()
            if out:
                remote_commit = out.split()[0]
        except Exception:
            pass

        # 2. Second attempt: GitHub REST API (if token provided or public)
        if not remote_commit:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"

            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get(f"{GITHUB_API_URL}/commits/main", headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        remote_commit = data.get("sha")
                        commit_message = data.get("commit", {}).get("message", "").split("\n")[0]
                        commit_date = data.get("commit", {}).get("author", {}).get("date")
                    elif resp.status_code in [401, 403, 404]:
                        logger.info(f"GitHub API returned {resp.status_code}. Private repo token required for API check.")
            except Exception as e:
                logger.warning(f"GitHub API check failed: {e}")

        # If remote could not be queried, fall back to current
        if not remote_commit:
            remote_commit = current["commit"]
            commit_message = current["message"]
            commit_date = current["date"]

        short_current = current["commit"][:7] if current["commit"] != "unknown" else "unknown"
        short_remote = remote_commit[:7] if remote_commit else "unknown"
        has_update = (short_current != short_remote) and (short_current != "unknown")

        return {
            "has_update": has_update,
            "current_version": CURRENT_VERSION,
            "current_commit": short_current,
            "latest_commit": short_remote,
            "commit_message": commit_message or "Latest SpecOPS updates available",
            "commit_date": commit_date or now_iso,
            "repo": f"{REPO_OWNER}/{REPO_NAME}",
            "last_checked_at": now_iso
        }

    def apply_update(self, token: Optional[str] = None) -> Dict[str, Any]:
        """
        Pulls latest code from GitHub main branch and updates requirements.
        """
        auth_token = token or self.token
        t0 = datetime.now(timezone.utc)

        try:
            # 1. Fetch from git
            if auth_token:
                git_url = f"https://x-access-token:{auth_token}@github.com/{REPO_OWNER}/{REPO_NAME}.git"
                subprocess.check_call(["git", "fetch", git_url, "main"], cwd=self.repo_dir, timeout=20.0)
                subprocess.check_call(["git", "reset", "--hard", "FETCH_HEAD"], cwd=self.repo_dir, timeout=10.0)
            else:
                subprocess.check_call(["git", "fetch", "origin", "main"], cwd=self.repo_dir, timeout=20.0)
                subprocess.check_call(["git", "reset", "--hard", "origin/main"], cwd=self.repo_dir, timeout=10.0)

            # 2. Run pip install if requirements exist
            req_file = os.path.join(self.repo_dir, "requirements.txt")
            venv_pip = os.path.join(self.repo_dir, ".venv", "bin", "pip")
            if os.path.exists(req_file) and os.path.exists(venv_pip):
                subprocess.check_call([venv_pip, "install", "-r", req_file, "-q", "--no-cache-dir"], cwd=self.repo_dir, timeout=60.0)

            new_commit = self.get_current_commit()

            return {
                "status": "success",
                "message": f"Successfully updated SpecOPS to commit {new_commit['short_commit']}.",
                "commit": new_commit["short_commit"],
                "commit_message": new_commit["message"],
                "restart_required": True
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Update command failed: {e}")
            return {
                "status": "error",
                "message": f"Update failed during git pull or pip install: {e}"
            }
        except Exception as e:
            logger.error(f"Unexpected error during update: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
