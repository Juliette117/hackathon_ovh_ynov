#!/usr/bin/env python3
import argparse
import html
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


SEVERITIES = [
    ("critical", "Critique", "criticalCount"),
    ("high", "Haute", "highCount"),
    ("medium", "Moyenne", "mediumCount"),
    ("low", "Basse", "lowCount"),
    ("unknown", "Inconnue", "unknownCount"),
]

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def run_kubectl(kubeconfig: str, args: list[str]) -> dict:
    # Le rapport est volontairement genere depuis Kubernetes, pas depuis un
    # fichier local, pour representer l'etat reel observe par Trivy Operator.
    command = ["kubectl"]
    if kubeconfig:
        command.extend(["--kubeconfig", kubeconfig])
    command.extend(args)

    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return json.loads(result.stdout)


def count(summary: dict, key: str) -> int:
    value = summary.get(key, 0)
    return int(value or 0)


def get_timestamp(item: dict) -> str:
    report = item.get("report", {})
    metadata = item.get("metadata", {})
    return (
        report.get("updateTimestamp")
        or metadata.get("creationTimestamp")
        or ""
    )


def image_from_report(item: dict) -> str:
    artifact = item.get("report", {}).get("artifact", {})
    repository = artifact.get("repository", "")
    tag = artifact.get("tag", "")
    if not repository or not tag:
        return ""
    return f"{repository}:{tag}"


def normalize_image(value: str) -> str:
    # Kubernetes peut declarer "nginx:1.27" alors que Trivy reporte
    # "library/nginx:1.27". Cette normalisation evite de confondre un ancien
    # rapport avec le scan de l'image actuellement attendue.
    image = value.strip()
    if not image:
        return ""
    if ":" not in image.rsplit("/", 1)[-1]:
        image = f"{image}:latest"
    if "/" not in image.split(":", 1)[0]:
        image = f"library/{image}"
    return image


def report_matches_image(item: dict, expected_image: str) -> bool:
    if not expected_image:
        return True
    return normalize_image(image_from_report(item)) == normalize_image(expected_image)


def find_latest_report(data: dict, workload: str, expected_image: str = "") -> dict:
    # Plusieurs ReplicaSets peuvent coexister apres des rollouts. On filtre donc
    # par workload puis, si fourni, par image attendue avant de prendre le scan le
    # plus recent.
    items = [
        item
        for item in data.get("items", [])
        if workload in item.get("metadata", {}).get("name", "")
        and report_matches_image(item, expected_image)
    ]
    if not items:
        suffix = f" et l'image {expected_image}" if expected_image else ""
        raise RuntimeError(f"Aucun VulnerabilityReport trouve pour {workload}{suffix}.")
    return sorted(items, key=get_timestamp)[-1]


def find_latest_config_report(data: dict, workload: str) -> Optional[dict]:
    items = [
        item
        for item in data.get("items", [])
        if workload in item.get("metadata", {}).get("name", "")
    ]
    if not items:
        return None
    return sorted(items, key=get_timestamp)[-1]


def format_date(value: str) -> str:
    if not value:
        return "inconnue"
    return value.replace("T", " ").replace("Z", " UTC")


def top_vulnerabilities(report: dict, limit: int = 12) -> list[dict]:
    # Le HTML doit rester lisible en soutenance: on montre les vulnerabilites les
    # plus urgentes, triees par severite, au lieu de noyer le lecteur.
    vulnerabilities = report.get("report", {}).get("vulnerabilities", [])
    return sorted(
        vulnerabilities,
        key=lambda vuln: (
            SEVERITY_ORDER.get(vuln.get("severity", "UNKNOWN"), 99),
            vuln.get("vulnerabilityID", ""),
        ),
    )[:limit]


def severity_badge(severity: str) -> str:
    css_class = severity.lower() if severity else "unknown"
    label = severity or "UNKNOWN"
    return f'<span class="tag {html.escape(css_class)}">{html.escape(label)}</span>'


def render_metric_cards(summary: dict) -> str:
    cards = []
    for css_class, label, key in SEVERITIES:
        cards.append(
            f"""
      <article class="metric {css_class}">
        <span>{html.escape(label)}</span>
        <strong>{count(summary, key)}</strong>
      </article>"""
        )
    return "".join(cards)


def render_bars(summary: dict) -> str:
    max_value = max([count(summary, key) for _, _, key in SEVERITIES] + [1])
    rows = []
    for css_class, label, key in SEVERITIES:
        value = count(summary, key)
        width = round((value / max_value) * 100, 1)
        rows.append(
            f"""
          <div class="bar-row">
            <span>{html.escape(label)}</span>
            <div class="track"><div class="fill {css_class}" style="width: {width}%;"></div></div>
            <strong>{value}</strong>
          </div>"""
        )
    return "".join(rows)


def render_config_bars(config_report: Optional[dict]) -> str:
    if not config_report:
        return "<p>Aucun ConfigAuditReport trouve pour ce workload.</p>"
    summary = config_report.get("report", {}).get("summary", {})
    return render_bars(summary)


def render_vulnerability_rows(report: dict) -> str:
    rows = []
    for vulnerability in top_vulnerabilities(report):
        severity = vulnerability.get("severity", "UNKNOWN")
        fixed_version = vulnerability.get("fixedVersion") or "-"
        rows.append(
            f"""
          <tr>
            <td>{severity_badge(severity)}</td>
            <td>{html.escape(vulnerability.get("vulnerabilityID", "-"))}</td>
            <td>{html.escape(vulnerability.get("resource", "-"))}</td>
            <td>{html.escape(vulnerability.get("installedVersion", "-"))}</td>
            <td>{html.escape(fixed_version)}</td>
          </tr>"""
        )
    if not rows:
        return """
          <tr>
            <td colspan="5">Aucune vulnerabilite listee dans le rapport.</td>
          </tr>"""
    return "".join(rows)


def render_html(vulnerability_report: dict, config_report: Optional[dict], namespace: str, workload: str) -> str:
    report = vulnerability_report.get("report", {})
    artifact = report.get("artifact", {})
    os_info = report.get("os", {})
    scanner = report.get("scanner", {})
    summary = report.get("summary", {})
    repository = artifact.get("repository", "inconnu")
    tag = artifact.get("tag", "inconnu")
    image = f"{repository}:{tag}"
    update_timestamp = get_timestamp(vulnerability_report)
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    critical = count(summary, "criticalCount")
    high = count(summary, "highCount")

    if critical == 0 and high == 0:
        risk_text = "Le dernier scan ne remonte plus de vulnerabilite critique ou haute sur l'image scannee."
        risk_class = "ok"
        risk_label = "OK"
    else:
        risk_text = "Le dernier scan contient encore des vulnerabilites critiques ou hautes a traiter."
        risk_class = "risk"
        risk_label = "!"

    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport Trivy - {html.escape(workload)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --panel-soft: #fbfcfe;
      --ink: #111827;
      --muted: #667085;
      --line: #dde3ec;
      --line-strong: #c8d1dc;
      --critical: #b42318;
      --high: #d92d20;
      --medium: #b54708;
      --low: #175cd3;
      --unknown: #475467;
      --ok: #067647;
      --shadow: 0 16px 40px rgb(17 24 39 / 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        linear-gradient(180deg, #eef3f8 0, var(--bg) 260px),
        var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 36px 0 52px;
    }}
    header {{
      display: grid;
      gap: 16px;
      margin-bottom: 24px;
      padding-bottom: 22px;
      border-bottom: 1px solid var(--line);
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(2.1rem, 4vw, 3.5rem); line-height: 1; letter-spacing: 0; font-weight: 780; }}
    h2 {{ font-size: 1rem; margin-bottom: 14px; font-weight: 720; color: #1f2937; }}
    .subtitle {{ color: var(--muted); max-width: 820px; font-size: 1rem; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .pill {{
      border: 1px solid var(--line);
      background: rgb(255 255 255 / 0.82);
      border-radius: 999px;
      padding: 7px 11px;
      color: var(--muted);
      font-size: 0.86rem;
      box-shadow: 0 1px 0 rgb(17 24 39 / 0.03);
    }}
    .grid {{ display: grid; gap: 16px; }}
    .cols-5 {{ grid-template-columns: repeat(5, minmax(0, 1fr)); }}
    .cols-2 {{ grid-template-columns: 1.15fr 0.85fr; align-items: start; }}
    .panel, .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .panel {{ padding: 18px; }}
    .metric {{
      position: relative;
      padding: 16px;
      min-height: 112px;
      display: grid;
      gap: 10px;
      align-content: space-between;
      overflow: hidden;
    }}
    .metric::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 5px;
      background: var(--unknown);
    }}
    .metric strong {{ font-size: 2rem; line-height: 1; font-weight: 760; }}
    .metric span {{ color: var(--muted); font-size: 0.82rem; font-weight: 650; text-transform: uppercase; }}
    .metric.critical::before {{ background: var(--critical); }}
    .metric.high::before {{ background: var(--high); }}
    .metric.medium::before {{ background: var(--medium); }}
    .metric.low::before {{ background: var(--low); }}
    .metric.unknown::before {{ background: var(--unknown); }}
    .bar-list {{ display: grid; gap: 13px; }}
    .bar-row {{ display: grid; grid-template-columns: 92px 1fr 44px; gap: 10px; align-items: center; font-size: 0.9rem; color: #344054; }}
    .bar-row strong {{ font-variant-numeric: tabular-nums; text-align: right; }}
    .track {{ height: 10px; overflow: hidden; background: #edf1f6; border-radius: 999px; }}
    .fill {{ height: 100%; border-radius: inherit; }}
    .fill.critical {{ background: var(--critical); }}
    .fill.high {{ background: var(--high); }}
    .fill.medium {{ background: var(--medium); }}
    .fill.low {{ background: var(--low); }}
    .fill.unknown {{ background: var(--unknown); }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.9rem; }}
    th, td {{ padding: 11px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 700; font-size: 0.74rem; text-transform: uppercase; background: var(--panel-soft); }}
    th:first-child {{ border-top-left-radius: 6px; }}
    th:last-child {{ border-top-right-radius: 6px; }}
    tr:last-child td {{ border-bottom: 0; }}
    td {{ color: #263244; }}
    .tag {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 3px 8px; color: #fff; font-size: 0.72rem; font-weight: 760; }}
    .tag.critical {{ background: var(--critical); }}
    .tag.high {{ background: var(--high); }}
    .tag.medium {{ background: var(--medium); }}
    .tag.low {{ background: var(--low); }}
    .tag.unknown {{ background: var(--unknown); }}
    .summary {{ display: grid; gap: 12px; }}
    .summary-item {{ display: grid; grid-template-columns: 30px 1fr; gap: 10px; align-items: start; color: #344054; }}
    .dot {{ width: 30px; height: 30px; display: grid; place-items: center; border-radius: 50%; color: #fff; font-weight: 800; font-size: 0.78rem; }}
    .dot.risk {{ background: var(--high); }}
    .dot.ok {{ background: var(--ok); }}
    code {{
      display: block;
      overflow-x: auto;
      padding: 12px;
      background: #111827;
      color: #dbeafe;
      border-radius: 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.82rem;
      white-space: pre;
      border: 1px solid #243044;
    }}
    footer {{ color: var(--muted); margin-top: 20px; font-size: 0.86rem; }}
    @media (max-width: 860px) {{
      .cols-5, .cols-2 {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: 78px 1fr 34px; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Rapport Trivy</h1>
      <p class="subtitle">
        Synthese generee depuis le dernier VulnerabilityReport Kubernetes pour
        <strong>{html.escape(namespace)}/{html.escape(workload)}</strong>.
      </p>
      <div class="meta">
        <span class="pill">Image: {html.escape(image)}</span>
        <span class="pill">OS: {html.escape(os_info.get("family", "inconnu"))} {html.escape(os_info.get("name", ""))}</span>
        <span class="pill">Scanner: {html.escape(scanner.get("name", "Trivy"))} {html.escape(scanner.get("version", ""))}</span>
        <span class="pill">Scan: {html.escape(format_date(update_timestamp))}</span>
        <span class="pill">HTML genere: {html.escape(generated_at)}</span>
      </div>
    </header>

    <section class="grid cols-5" aria-label="Resume des vulnerabilites">
{render_metric_cards(summary)}
    </section>

    <section class="grid cols-2" style="margin-top: 16px;">
      <article class="panel">
        <h2>Distribution par severite</h2>
        <div class="bar-list">{render_bars(summary)}
        </div>
      </article>

      <article class="panel">
        <h2>Lecture rapide</h2>
        <div class="summary">
          <div class="summary-item">
            <span class="dot {risk_class}">{html.escape(risk_label)}</span>
            <p>{html.escape(risk_text)}</p>
          </div>
          <div class="summary-item">
            <span class="dot ok">G</span>
            <p>Le rapport provient de Trivy Operator et se regenere depuis les objets Kubernetes.</p>
          </div>
          <div class="summary-item">
            <span class="dot ok">PR</span>
            <p>La correction attendue est versionnee dans Git, puis appliquee par Argo CD apres merge.</p>
          </div>
        </div>
      </article>
    </section>

    <section class="panel" style="margin-top: 16px;">
      <h2>Vulnerabilites prioritaires</h2>
      <table>
        <thead>
          <tr>
            <th>Severite</th>
            <th>CVE</th>
            <th>Package</th>
            <th>Version installee</th>
            <th>Version corrigee</th>
          </tr>
        </thead>
        <tbody>{render_vulnerability_rows(vulnerability_report)}
        </tbody>
      </table>
    </section>

    <section class="grid cols-2" style="margin-top: 16px;">
      <article class="panel">
        <h2>Audit de configuration</h2>
        <div class="bar-list">{render_config_bars(config_report)}
        </div>
      </article>

      <article class="panel">
        <h2>Commandes</h2>
        <code>python3 scripts/generate_trivy_report.py

python3 scripts/generate_trivy_report.py --watch

kubectl --kubeconfig infra/kubeconfig.yaml get vulnerabilityreports,configauditreports -n {html.escape(namespace)}</code>
      </article>
    </section>

    <footer>
      Artefact genere automatiquement depuis Trivy Operator.
    </footer>
  </main>
</body>
</html>
"""


def write_report(args: argparse.Namespace) -> str:
    # Trivy Operator expose ses resultats sous forme de CRD Kubernetes:
    # VulnerabilityReport pour les images, ConfigAuditReport pour les manifests.
    vulnerability_data = run_kubectl(
        args.kubeconfig,
        ["get", "vulnerabilityreports", "-n", args.namespace, "-o", "json"],
    )
    config_data = run_kubectl(
        args.kubeconfig,
        ["get", "configauditreports", "-n", args.namespace, "-o", "json"],
    )
    vulnerability_report = find_latest_report(
        vulnerability_data,
        args.workload,
        args.expected_image,
    )
    config_report = find_latest_config_report(config_data, args.workload)
    content = render_html(
        vulnerability_report,
        config_report,
        namespace=args.namespace,
        workload=args.workload,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return get_timestamp(vulnerability_report)


def main() -> int:
    parser = argparse.ArgumentParser(description="Genere un rapport HTML Trivy depuis Kubernetes.")
    # Par defaut : infra/kubeconfig.yaml s'il existe (poste local), sinon la
    # chaine standard kubectl (KUBECONFIG ou ~/.kube/config — cas CI).
    default_kubeconfig = "infra/kubeconfig.yaml" if Path("infra/kubeconfig.yaml").exists() else ""
    parser.add_argument("--kubeconfig", default=default_kubeconfig)
    parser.add_argument("--namespace", default="demo")
    parser.add_argument("--workload", default="vulnerable-web")
    parser.add_argument("--output", default="docs/artifacts/trivy-report.html")
    parser.add_argument("--expected-image", default="")
    parser.add_argument("--wait-timeout", type=int, default=0)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=20)
    args = parser.parse_args()

    try:
        deadline = time.time() + args.wait_timeout
        while True:
            try:
                last_timestamp = write_report(args)
                break
            except RuntimeError:
                # Apres un changement GitOps, Argo CD puis Trivy Operator ont
                # besoin de temps pour deployer et scanner la nouvelle image.
                if not args.wait_timeout or time.time() >= deadline:
                    raise
                print("Rapport Trivy pas encore disponible, nouvelle tentative...")
                time.sleep(args.interval)

        print(f"Rapport HTML mis a jour: {args.output} ({last_timestamp})")
        if not args.watch:
            return 0

        while True:
            time.sleep(args.interval)
            timestamp = write_report(args)
            if timestamp != last_timestamp:
                last_timestamp = timestamp
                print(f"Nouveau scan detecte: {timestamp}")
            else:
                print(f"Aucun nouveau scan: {timestamp}")
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
