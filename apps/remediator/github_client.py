import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional


class GitHubError(RuntimeError):
    pass


def normalize_repo(repo: str) -> str:
    # L'utilisateur peut fournir owner/repo ou l'URL Git remote. On normalise
    # pour appeler l'API GitHub avec un format unique.
    repo = repo.strip()
    if repo.startswith("git@github.com:"):
        repo = repo.removeprefix("git@github.com:")
    elif repo.startswith("https://github.com/"):
        repo = repo.removeprefix("https://github.com/")
    elif repo.startswith("http://github.com/"):
        repo = repo.removeprefix("http://github.com/")

    if repo.endswith(".git"):
        repo = repo[:-4]
    repo = repo.strip("/")

    if repo.count("/") != 1:
        raise GitHubError(
            "GITHUB_REPO doit etre au format owner/repo "
            "ou une URL GitHub du type https://github.com/owner/repo.git."
        )
    return repo


@dataclass(frozen=True)
class GitHubConfig:
    token: str
    repo: str
    base_branch: str = "main"

    def __post_init__(self) -> None:
        object.__setattr__(self, "repo", normalize_repo(self.repo))


class GitHubClient:
    def __init__(self, config: GitHubConfig):
        self.config = config
        self.api_base = f"https://api.github.com/repos/{config.repo}"

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> dict:
        # Client volontairement base sur la bibliotheque standard: le script peut
        # tourner dans GitHub Actions sans installer de dependance GitHub.
        data = None
        headers = {
            "Authorization": f"Bearer {self.config.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            self.api_base + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise GitHubError(f"Erreur GitHub HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"Impossible de joindre GitHub: {exc}") from exc

        if not body:
            return {}
        return json.loads(body)

    def get_branch_sha(self, branch: str) -> str:
        data = self._request("GET", f"/git/ref/heads/{urllib.parse.quote(branch)}")
        return data["object"]["sha"]

    def upsert_branch(self, branch: str, sha: str) -> None:
        # GET utilise /git/ref/... (singulier), PATCH exige /git/refs/... (pluriel).
        # Si la branche existe deja, on la replace sur la base courante pour que
        # la PR automatique reste lisible et rejouable.
        try:
            self._request("GET", f"/git/ref/heads/{urllib.parse.quote(branch)}")
        except GitHubError as exc:
            if "HTTP 404" not in str(exc):
                raise
            self._request(
                "POST",
                "/git/refs",
                {"ref": f"refs/heads/{branch}", "sha": sha},
            )
            return

        self._request(
            "PATCH",
            f"/git/refs/heads/{urllib.parse.quote(branch)}",
            {"sha": sha, "force": True},
        )

    def get_file_sha(self, path: str, branch: str) -> str:
        encoded_path = urllib.parse.quote(path)
        data = self._request("GET", f"/contents/{encoded_path}?ref={urllib.parse.quote(branch)}")
        return data["sha"]

    def update_file(self, path: str, branch: str, content: str, message: str) -> str:
        sha = self.get_file_sha(path, branch)
        payload = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": branch,
        }
        data = self._request("PUT", f"/contents/{urllib.parse.quote(path)}", payload)
        return data["commit"]["html_url"]

    def find_open_pr(self, branch: str, base_branch: str) -> Optional[str]:
        query = urllib.parse.urlencode(
            {
                "state": "open",
                "head": f"{self.config.repo.split('/')[0]}:{branch}",
                "base": base_branch,
            }
        )
        prs = self._request("GET", f"/pulls?{query}")
        if prs:
            return prs[0]["html_url"]
        return None

    def create_pull_request(
        self,
        branch: str,
        base_branch: str,
        title: str,
        body: str,
    ) -> str:
        # Si une PR de remediation existe deja, on la reutilise au lieu d'en
        # creer une nouvelle a chaque scan/push.
        existing = self.find_open_pr(branch, base_branch)
        if existing:
            return existing

        data = self._request(
            "POST",
            "/pulls",
            {
                "title": title,
                "head": branch,
                "base": base_branch,
                "body": body,
            },
        )
        return data["html_url"]
