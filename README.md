# Hackathon OVHcloud × Ynov — Chaîne d'audit et de remédiation GitOps

Boucle de sécurité automatisée sur Kubernetes managé OVHcloud : une faille est
détectée (Trivy/Kyverno/Falco), une IA (AI Endpoints OVHcloud) propose le
correctif, une Pull Request s'ouvre automatiquement, un humain valide, Argo CD
déploie. Cas d'usage : un portail patient-médecin volontairement vulnérable.

> Pour le **pourquoi** et le **comment** de l'architecture, voir le
> [rapport d'architecture](docs/rapport-architecture.md). Ce README ne couvre
> que le **faire tourner**.

## 📦 Les livrables

| Livrable | Emplacement |
|---|---|
| Rapport d'architecture (1-2 pages) | [`docs/rapport-architecture.md`](docs/rapport-architecture.md) |
| Tableau récapitulatif du statut CNCF | inclus à la fin du rapport d'architecture |
| Code de la couche d'enrichissement IA | [`apps/remediator/`](apps/remediator/) (+ son [README](apps/remediator/README.md)) |
| Dépôt géré par Argo CD (app-of-apps) | [`infra/argocd-apps/`](infra/argocd-apps/) |
| Policies Kyverno | [`policies/`](policies/) |
| Workload volontairement vulnérable | [`apps/vulnerable-app/`](apps/vulnerable-app/) (variante vulnérable : [`docs/demo/deployment-vulnerable.yaml`](docs/demo/deployment-vulnerable.yaml)) |
| Rapport Trivy HTML (généré par CI) | [`docs/artifacts/trivy-report.html`](docs/artifacts/trivy-report.html) |

## 🚀 Installation (une seule fois)

Prérequis : `kubectl`, `helm`, `git`, Python 3.11+, et le **kubeconfig** du
cluster OVHcloud (Manager OVH → Managed Kubernetes → votre cluster →
kubeconfig). Ne jamais le committer — le `.gitignore` bloque `kubeconfig*`.

```sh
# 1. Installer le kubeconfig
mkdir -p ~/.kube && cp /chemin/vers/kubeconfig.yml ~/.kube/config
kubectl get nodes   # les 3 nodes doivent etre Ready

# 2. Amorcer Argo CD (seule installation manuelle de tout le projet)
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 3. Amorcer l'app-of-apps : Argo CD installe ensuite TOUT le reste
#    (Trivy, Kyverno, Falco, Prometheus, Loki, l'app demo...) depuis Git
kubectl apply -f infra/argocd-apps/root-app.yaml
```

Après quelques minutes, `kubectl get applications -n argocd` doit montrer
toutes les applications `Synced / Healthy`.

## 🖥️ Lancer / arrêter les interfaces

```sh
bash scripts/start-interfaces.sh    # lance tous les tunnels
bash scripts/stop-interfaces.sh     # les arrete
```

| Interface | URL | Identifiants |
|---|---|---|
| Argo CD | https://51.210.2.115 (exposé en LoadBalancer) | `admin` / secret initial* |
| Grafana | http://127.0.0.1:3001 | `admin` / `hackathon2026` |
| Falco UI | http://127.0.0.1:2803 | `admin` / `admin` |
| Argo Rollouts | http://127.0.0.1:3101 | — |
| Portail démo | http://127.0.0.1:8080 | — |

*Mot de passe Argo CD :
`kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d`

Sous Windows/Git Bash, les messages « pas encore joignable » du script sont des
faux négatifs (`nc` absent) — les tunnels fonctionnent.

## 🤖 Le remédiateur IA

Configuration et utilisation détaillées : [`apps/remediator/README.md`](apps/remediator/README.md).
En résumé : copier `.env.example` vers `.env`, renseigner les tokens (OVH AI +
GitHub), puis :

```sh
python apps/remediator/remediator.py test-ai        # verifier la connexion IA
python apps/remediator/remediator.py create-pr \
  --manifest apps/vulnerable-app/deployment.yaml \
  --report apps/remediator/sample-report.txt \
  --repo-path apps/vulnerable-app/deployment.yaml   # boucle complete -> PR
```

Le même mécanisme tourne aussi en CI : le workflow **AI remediation PR** se
déclenche automatiquement à chaque modification de `apps/vulnerable-app/` et
ouvre la Pull Request tout seul.

## 🎬 Dérouler une démo

1. **Introduire la faille** (image de 2018, conteneur privilégié, root, sans limites) :
   ```sh
   cp docs/demo/deployment-vulnerable.yaml apps/vulnerable-app/deployment.yaml
   git commit -am "demo: reintroduction de la faille" && git push
   ```
   Argo CD déploie la version vulnérable (≤3 min). Le portail continue de
   fonctionner — c'est tout le problème.
2. **Constater la détection** :
   ```sh
   kubectl get vulnerabilityreports -n demo      # CVE detectees par Trivy
   kubectl get policyreports -n demo             # violations des policies Kyverno
   ```
   Dans Grafana (Explore → Prometheus) :
   `sum(trivy_image_vulnerabilities{namespace="demo", severity="Critical"})`
3. **Simuler une intrusion** (alerte Falco en direct dans la Falco UI) :
   ```sh
   kubectl exec -it deploy/vulnerable-web -n demo -- sh -c "cat /etc/shadow"
   ```
4. **Laisser l'IA proposer le correctif** : la PR s'ouvre automatiquement via
   la CI (ou lancer `create-pr` à la main, cf. section précédente).
5. **Relire la PR** (la revue humaine est le garde-fou : vérifier le YAML
   proposé), puis **merger**.
6. **Regarder la boucle se fermer** : Argo CD resynchronise, les pods
   redémarrent en version durcie, le portail reste en ligne, et la courbe de
   CVE critiques chute dans Grafana (~5 min entre merge et chute).

La boucle est rejouable à volonté : refaire l'étape 1.

## ⚙️ CI (GitHub Actions)

| Workflow | Rôle |
|---|---|
| `security-checks` | validation YAML/Python, détection de secrets (Gitleaks), scan de config Trivy — bloque les mauvaises configs avant le cluster |
| `ai-remediation` | ouvre la PR de remédiation IA quand le workload change |
| `trivy-report` | régénère `docs/artifacts/trivy-report.html` depuis le scan réel du cluster |

Note : `security-checks` passe volontairement au rouge quand la version
vulnérable est poussée (étape 1 de la démo) — c'est la détection en amont qui
fait son travail, les artefacts de démo dans `docs/` étant eux exclus du scan.
