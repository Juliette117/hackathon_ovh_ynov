# Remediateur IA

Le remédiateur lit un rapport de sécurité, demande un YAML corrigé à OVH AI Endpoints, puis peut ouvrir une Pull Request GitHub automatiquement.

## Configuration

Copier l'exemple :

```sh
cp apps/remediator/.env.example apps/remediator/.env
```

Remplir `apps/remediator/.env` :

```env
OVH_AI_TOKEN=...
OVH_AI_BASE_URL=https://oai.endpoints.kepler.ai.cloud.ovh.net/v1
OVH_AI_MODEL=gpt-oss-20b

GITHUB_TOKEN=...
GITHUB_REPO=Juliette117/hackathon_ovh_ynov
GITHUB_BASE_BRANCH=main
```

Le vrai fichier `.env` est ignoré par Git.

## Tester l'IA

```sh
python3 apps/remediator/remediator.py diagnose-ai
python3 apps/remediator/remediator.py test-ai
```

## Générer un YAML local

```sh
python3 apps/remediator/remediator.py propose-fix \
  --manifest apps/vulnerable-app/deployment.yaml \
  --report apps/remediator/sample-report.txt \
  --output /tmp/fixed-deployment.yaml
```

## Ouvrir une Pull Request automatiquement

```sh
python3 apps/remediator/remediator.py create-pr \
  --manifest apps/vulnerable-app/deployment.yaml \
  --report apps/remediator/sample-report.txt \
  --repo-path apps/vulnerable-app/deployment.yaml
```

La commande :

1. lit le manifest local ;
2. lit le rapport ;
3. demande un correctif YAML à l'IA ;
4. crée ou remet à jour la branche `fix/ai-remediation` depuis `main` ;
5. commit le YAML corrigé sur GitHub ;
6. ouvre une Pull Request, ou réutilise la PR ouverte existante.

Le token GitHub doit avoir les droits `Contents: Read/Write` et `Pull requests: Read/Write` sur le dépôt.
