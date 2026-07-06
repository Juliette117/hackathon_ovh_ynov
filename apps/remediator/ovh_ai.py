import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse
from dataclasses import dataclass


class OvhAiError(RuntimeError):
    pass


@dataclass(frozen=True)
class OvhAiConfig:
    token: str
    base_url: str
    model: str

    @classmethod
    def from_env(cls) -> "OvhAiConfig":
        token = os.environ.get("OVH_AI_TOKEN", "").strip()
        base_url = os.environ.get("OVH_AI_BASE_URL", "").strip()
        model = os.environ.get("OVH_AI_MODEL", "").strip()

        missing = [
            name
            for name, value in (
                ("OVH_AI_TOKEN", token),
                ("OVH_AI_BASE_URL", base_url),
                ("OVH_AI_MODEL", model),
            )
            if not value
        ]
        if missing:
            raise OvhAiError(
                "Variables manquantes: "
                + ", ".join(missing)
                + ". Exportez-les avant de lancer le script."
            )

        return cls(token=token, base_url=normalize_base_url(base_url), model=model)


def normalize_base_url(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    for suffix in ("/chat/completions", "/models"):
        if base_url.endswith(suffix):
            base_url = base_url[: -len(suffix)]
    if base_url.endswith("/v1"):
        return base_url
    if "oai.endpoints.kepler.ai.cloud.ovh.net" in base_url:
        return base_url + "/v1"
    if "endpoints.kepler.ai.cloud.ovh.net" in base_url:
        return base_url + "/api/openai_compat/v1"
    return base_url


def candidate_base_urls(base_url: str) -> list[str]:
    raw = base_url.rstrip("/")
    for suffix in ("/chat/completions", "/models"):
        if raw.endswith(suffix):
            raw = raw[: -len(suffix)]

    candidates = [normalize_base_url(raw)]
    if not raw.endswith("/v1"):
        candidates.append(raw + "/v1")
        candidates.append(raw + "/api/openai_compat/v1")
    else:
        parsed = urlparse(raw)
        host_only = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        if host_only:
            candidates.append(host_only + "/api/openai_compat/v1")
            candidates.append(host_only + "/v1")

    deduped = []
    for candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped


class OvhAiClient:
    def __init__(self, config: OvhAiConfig):
        self.config = config

    def chat(self, messages: list[dict[str, str]], max_tokens: int = 1200) -> str:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.config.base_url + "/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise OvhAiError(
                f"Erreur HTTP {exc.code} depuis OVH AI. Reponse: {body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise OvhAiError(f"Impossible de joindre OVH AI: {exc}") from exc

        try:
            parsed = json.loads(body)
            message = parsed["choices"][0]["message"]
            content = message.get("content")
            if content:
                return content
            reasoning = message.get("reasoning")
            if reasoning:
                raise OvhAiError(
                    "Le modele a repondu avec du raisonnement mais sans contenu final. "
                    "Augmentez max_tokens ou utilisez un modele non-reasoning."
                )
            raise KeyError("choices[0].message.content")
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise OvhAiError(f"Reponse OVH AI inattendue: {body}") from exc


def probe_chat(base_url: str, token: str, model: str) -> tuple[int, str]:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reponds uniquement OK"}],
        "max_tokens": 20,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        return 0, str(exc)
