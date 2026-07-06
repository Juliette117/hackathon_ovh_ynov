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


def find_latest_report(data: dict, workload: str) -> dict:
    items = [
        item
        for item in data.get("items", [])
        if workload in item.get("metadata", {}).get("name", "")
    ]
    if not items:
        raise RuntimeError(f"Aucun VulnerabilityReport trouve pour {workload}.")
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
      --bg: #f4f7fb;
      --panel: #ffffff;
      --ink: #162033;
      --muted: #617086;
      --line: #d8e0ea;
      --critical: #9f1239;
      --high: #dc2626;
      --medium: #d97706;
      --low: #2563eb;
      --unknown: #64748b;
      --ok: #15803d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0 48px;
    }}
    header {{ display: grid; gap: 14px; margin-bottom: 24px; }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(2rem, 4vw, 4rem); line-height: 1; letter-spacing: 0; }}
    h2 {{ font-size: 1.15rem; margin-bottom: 14px; }}
    .subtitle {{ color: var(--muted); max-width: 820px; font-size: 1.02rem; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .pill {{
      border: 1px solid var(--line);
      background: #fff;
      border-radius: 999px;
      padding: 7px 10px;
      color: var(--muted);
      font-size: 0.86rem;
    }}
    .grid {{ display: grid; gap: 16px; }}
    .cols-5 {{ grid-template-columns: repeat(5, minmax(0, 1fr)); }}
    .cols-2 {{ grid-template-columns: 1.15fr 0.85fr; align-items: start; }}
    .panel, .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 12px 28px rgb(22 32 51 / 0.06);
    }}
    .panel {{ padding: 18px; }}
    .metric {{ padding: 16px; min-height: 124px; display: grid; gap: 10px; align-content: space-between; }}
    .metric strong {{ font-size: 2.2rem; line-height: 1; }}
    .metric span {{ color: var(--muted); font-size: 0.9rem; }}
    .metric.critical {{ border-top: 5px solid var(--critical); }}
    .metric.high {{ border-top: 5px solid var(--high); }}
    .metric.medium {{ border-top: 5px solid var(--medium); }}
    .metric.low {{ border-top: 5px solid var(--low); }}
    .metric.unknown {{ border-top: 5px solid var(--unknown); }}
    .bar-list {{ display: grid; gap: 13px; }}
    .bar-row {{ display: grid; grid-template-columns: 92px 1fr 44px; gap: 10px; align-items: center; font-size: 0.92rem; }}
    .track {{ height: 13px; overflow: hidden; background: #e8eef5; border-radius: 999px; }}
    .fill {{ height: 100%; border-radius: inherit; }}
    .fill.critical {{ background: var(--critical); }}
    .fill.high {{ background: var(--high); }}
    .fill.medium {{ background: var(--medium); }}
    .fill.low {{ background: var(--low); }}
    .fill.unknown {{ background: var(--unknown); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; }}
    .tag {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 3px 8px; color: #fff; font-size: 0.76rem; font-weight: 700; }}
    .tag.critical {{ background: var(--critical); }}
    .tag.high {{ background: var(--high); }}
    .tag.medium {{ background: var(--medium); }}
    .tag.low {{ background: var(--low); }}
    .tag.unknown {{ background: var(--unknown); }}
    .summary {{ display: grid; gap: 12px; }}
    .summary-item {{ display: grid; grid-template-columns: 28px 1fr; gap: 10px; align-items: start; }}
    .dot {{ width: 28px; height: 28px; display: grid; place-items: center; border-radius: 50%; color: #fff; font-weight: 800; font-size: 0.85rem; }}
    .dot.risk {{ background: var(--high); }}
    .dot.ok {{ background: var(--ok); }}
    code {{
      display: block;
      overflow-x: auto;
      padding: 12px;
      background: #101827;
      color: #dbeafe;
      border-radius: 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.82rem;
      white-space: pre;
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
    vulnerability_data = run_kubectl(
        args.kubeconfig,
        ["get", "vulnerabilityreports", "-n", args.namespace, "-o", "json"],
    )
    config_data = run_kubectl(
        args.kubeconfig,
        ["get", "configauditreports", "-n", args.namespace, "-o", "json"],
    )
    vulnerability_report = find_latest_report(vulnerability_data, args.workload)
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
    parser.add_argument("--kubeconfig", default="infra/kubeconfig.yaml")
    parser.add_argument("--namespace", default="demo")
    parser.add_argument("--workload", default="vulnerable-web")
    parser.add_argument("--output", default="docs/artifacts/trivy-report.html")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=20)
    args = parser.parse_args()

    try:
        last_timestamp = write_report(args)
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
