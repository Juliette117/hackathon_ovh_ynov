import argparse
import re
import sys
from pathlib import Path

from ovh_ai import (
    OvhAiClient,
    OvhAiConfig,
    OvhAiError,
    candidate_base_urls,
    probe_chat,
)


SYSTEM_PROMPT = """Tu es un expert Kubernetes et securite cloud.
Tu dois proposer des correctifs YAML minimaux, lisibles et valides.
Ne supprime pas les noms, namespaces, labels ou selectors existants sauf necessite.

Reponds strictement avec ce format:

EXPLICATION:
<3 a 6 lignes en francais>

YAML:
```yaml
<manifest complet corrige>
```
"""


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    import os

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def build_fix_prompt(report: str, manifest: str) -> str:
    return f"""Voici un rapport de securite Kubernetes:

{report}

Voici le manifest actuel:

```yaml
{manifest}
```

Corrige les problemes de securite visibles. Si une image est vulnerable ou ancienne,
propose une image plus recente. Ajoute un securityContext non-root et des ressources
CPU/memoire raisonnables si elles manquent.
"""


def extract_yaml(ai_text: str) -> str:
    match = re.search(r"```yaml\s*(.*?)```", ai_text, re.DOTALL | re.IGNORECASE)
    if not match:
        raise OvhAiError("L'IA n'a pas renvoye de bloc ```yaml ... ```.")
    return match.group(1).strip() + "\n"


def test_ai(_: argparse.Namespace) -> int:
    client = OvhAiClient(OvhAiConfig.from_env())
    answer = client.chat(
        [{"role": "user", "content": "Reponds uniquement avec le mot OK."}],
        max_tokens=120,
    )
    print(answer.strip())
    return 0


def diagnose_ai(_: argparse.Namespace) -> int:
    import os

    token = os.environ.get("OVH_AI_TOKEN", "").strip()
    raw_base_url = os.environ.get("OVH_AI_BASE_URL", "").strip()
    model = os.environ.get("OVH_AI_MODEL", "").strip()

    if not token or not raw_base_url or not model:
        raise OvhAiError(
            "Variables manquantes pour le diagnostic: OVH_AI_TOKEN, "
            "OVH_AI_BASE_URL, OVH_AI_MODEL."
        )

    print(f"Token: present, longueur={len(token)}")
    print(f"Modele: {model}")
    print(f"URL fournie: {raw_base_url}")
    print()

    for base_url in candidate_base_urls(raw_base_url):
        status, body = probe_chat(base_url, token, model)
        preview = " ".join(body.strip().split())[:240]
        print(f"[{status}] {base_url}/chat/completions")
        print(f"  {preview}")
        if status == 200:
            print()
            print("OK: cette URL fonctionne. Utilisez:")
            print(f"OVH_AI_BASE_URL={base_url}")
            return 0

    print()
    print("Aucune route testee n'a repondu en 200.")
    print("Si vous voyez surtout 404 no Route matched, l'URL/domaine n'est pas celui de l'API du modele.")
    print("Si vous voyez 401/403, le token est invalide ou non autorise.")
    print("Si vous voyez 400/422, le modele ou le payload est probablement incorrect.")
    return 1


def propose_fix(args: argparse.Namespace) -> int:
    manifest = Path(args.manifest).read_text(encoding="utf-8")
    report = Path(args.report).read_text(encoding="utf-8")

    client = OvhAiClient(OvhAiConfig.from_env())
    ai_text = client.chat(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_fix_prompt(report, manifest)},
        ],
        max_tokens=args.max_tokens,
    )
    fixed_yaml = extract_yaml(ai_text)

    if args.output:
        Path(args.output).write_text(fixed_yaml, encoding="utf-8")
        print(f"YAML corrige ecrit dans {args.output}")
    else:
        print(fixed_yaml)

    return 0


def main() -> int:
    load_dotenv(Path("apps/remediator/.env"))

    parser = argparse.ArgumentParser(description="Remediateur IA OVH")
    subparsers = parser.add_subparsers(dest="command", required=True)

    test_parser = subparsers.add_parser("test-ai", help="Teste OVH AI Endpoints")
    test_parser.set_defaults(func=test_ai)

    diagnose_parser = subparsers.add_parser(
        "diagnose-ai", help="Teste plusieurs routes OVH AI possibles"
    )
    diagnose_parser.set_defaults(func=diagnose_ai)

    fix_parser = subparsers.add_parser("propose-fix", help="Genere un YAML corrige")
    fix_parser.add_argument("--manifest", required=True)
    fix_parser.add_argument("--report", required=True)
    fix_parser.add_argument("--output")
    fix_parser.add_argument("--max-tokens", type=int, default=1800)
    fix_parser.set_defaults(func=propose_fix)

    args = parser.parse_args()
    try:
        return args.func(args)
    except OvhAiError as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
