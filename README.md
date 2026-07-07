## Hackathon OVHcloud × Ynov — Projet de remédiation de sécurité assistée par IA

Ce projet met en place une chaîne DevSecOps complète et fonctionnelle sur Kubernetes, dont l'objectif est d'automatiser la correction de failles de sécurité en utilisant l'IA comme un acteur proactif de la remédiation.

La chaîne est déployée sur un cluster Kubernetes managé OVHcloud et toutes les briques communiquent entre elles. Le scénario principal — détecter une faille, la faire corriger par une IA, valider le correctif via une Pull Request, et le déployer automatiquement — est reproductible de bout en bout.

Des scripts sont fournis pour lancer et arrêter facilement les interfaces de démonstration (Grafana, Argo CD, Falco UI, etc.).

### Contexte du projet

Nous nous sommes projetés dans la peau d'une **équipe DevSecOps gérant une application critique** (ici, un portail patient-médecin) en production sur Kubernetes.

Dans ce contexte, la sécurité n'est pas une option. Chaque jour, de nouvelles vulnérabilités (CVE) sont découvertes dans les composants logiciels que nous utilisons. Le temps entre la détection d'une faille et son déploiement en production est une fenêtre de risque critique.


### Solution technique

Nous avons construit une **boucle de remédiation automatisée et contrôlée**, où l'IA devient un co-pilote actif de la sécurité.

Le flux est le suivant :

```mermaid
graph TD
    A[1. Détection continue] -- Rapport de failles --> B;
    subgraph Cluster Kubernetes
        A(Applications);
    end

    B(2. Remédiateur IA) -- Demande de correction --> C{3. OVH AI Endpoints};
    C -- Manifeste YAML corrigé --> B;

    B -- Crée une Pull Request --> D[4. GitHub];
    subgraph Dépôt Git
        D;
    end

    D -- Revue & Merge --> E[5. Validation Humaine];
    E -- Déclenche --> F(6. Argo CD);

    F -- Déploie le correctif --> G[7. Cluster Corrigé];
    subgraph Cluster Kubernetes
        G;
    end
```

**Briques techniques clés :**
*   **GitOps (Argo CD)** : Git est la seule source de vérité. Tout déploiement passe par un `git push`.
*   **Sécurité multi-couches (Trivy, Kyverno, Falco)** : Nous scannons les images, les configurations d'infrastructure-as-code et les menaces à l'exécution.
*   **Remédiation par IA (Script `remediator` + OVH AI Endpoints)** : Notre script Python prend un rapport de sécurité, le soumet à une IA avec le manifeste actuel, et récupère une proposition de correctif.
*   **Validation "Human-in-the-loop"** : L'IA ne merge jamais automatiquement. Elle crée une Pull Request détaillée que l'équipe doit valider. C'est notre garde-fou essentiel.
*   **Déploiement sécurisé (Argo Rollouts)** : Le correctif est déployé progressivement (canary) pour s'assurer qu'il ne casse pas l'application.
*   **Observabilité complète (Prometheus, Grafana, Loki)** : Nous surveillons l'état de la sécurité et la santé de l'application en temps réel.


