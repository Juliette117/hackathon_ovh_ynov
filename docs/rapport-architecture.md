# Rapport d'architecture — Chaîne d'audit et de remédiation GitOps sécurisée

**Hackathon Lille Ynov Campus × OVHcloud — 6-7 juillet 2026**

## 1. Ce qu'on a construit

L'idée du brief, c'est de faire de l'IA un maillon actif de la sécurité, pas juste un assistant qu'on consulte à côté. Concrètement, on a mis en place une boucle qui part d'une faille détectée dans le cluster et qui va jusqu'au correctif appliqué : une IA propose la correction, un humain la valide, et le cluster se met à jour tout seul.

```
Détection (Trivy / Kyverno)
        │
        ▼
Analyse + correctif proposé par l'IA (AI Endpoints OVHcloud)
        │
        ▼
Pull Request automatique sur GitHub (script remédiateur)
        │
        ▼
Revue humaine → merge
        │
        ▼
Argo CD resynchronise
        │
        ▼
Cluster corrigé
```

Toute la chaîne tourne sur un cluster Kubernetes managé OVHcloud. La règle qu'on s'est fixée : tout ce qui est déployé passe par Git. Personne ne touche au cluster à la main — la seule exception, c'est l'installation initiale d'Argo CD, et c'est assumé.

## 2. Rôle de chaque brique

**Argo CD** est le chef d'orchestre : il surveille notre dépôt Git et fait en sorte que le cluster corresponde toujours à ce qui y est écrit. On déploie en faisant un commit, plus rien d'autre. Une application "racine" surveille un dossier du dépôt : ajouter un composant revient à y ajouter un fichier, et Argo CD l'installe tout seul.

**Argo Rollouts** complète Argo CD sur la partie déploiement progressif : Argo CD applique l'état voulu depuis Git, puis Argo Rollouts permet de contrôler comment une nouvelle version arrive réellement en production. Au lieu de remplacer toute l'application d'un coup, on peut faire un canary, un blue/green ou un rollback si la nouvelle version se comporte mal. Dans notre contexte, c'est particulièrement utile après une correction de sécurité : on ne veut pas qu'une image corrigée mais instable casse tout le service.

**Trivy-operator** est notre antivirus : il scanne en continu les images de nos applications et liste les failles connues (les CVE), avec pour chacune la version qui la corrige. Ses rapports sont stockés directement dans le cluster, ce qui permet à notre script de les lire facilement. C'est la matière première de l'IA.

**Kyverno** est notre contrôle qualité : il vérifie chaque application contre trois règles écrites par nous — pas de conteneur privilégié, pas de tag d'image flottant, des limites de ressources obligatoires. Il tourne en mode "signalement" plutôt que "blocage" : s'il bloquait, notre propre application vulnérable ne pourrait pas exister et on n'aurait plus rien à démontrer. Ses violations sont une deuxième source de données pour l'IA.

**Falco** est notre alarme : là où Trivy et Kyverno analysent des fichiers, Falco regarde ce qui se passe en direct dans les conteneurs. Si quelqu'un ouvre un terminal dans un conteneur ou lit un fichier sensible, il alerte immédiatement. C'est ce qui couvre les attaques en cours, invisibles pour l'analyse statique.

**Prometheus et Grafana** mesurent tout ça : Prometheus collecte le nombre de failles détectées par Trivy, et Grafana l'affiche en graphique. Pendant la démo, on voit littéralement la courbe des failles critiques chuter au moment où la correction est appliquée.

**Fluent Bit et Loki** ajoutent la partie logs : Fluent Bit tourne sur chaque nœud du cluster et collecte les logs produits par les conteneurs Kubernetes. Il les enrichit avec des labels utiles comme le namespace, le pod et le conteneur, puis les envoie vers Loki. Loki centralise ces logs et permet de les interroger avec LogQL, directement depuis Grafana. Cela permet de passer d'une alerte ou d'un changement de déploiement à la preuve opérationnelle : est-ce que l'application logue encore correctement après correction ? est-ce qu'un pod génère des erreurs ? est-ce qu'un événement de sécurité Falco correspond à des logs applicatifs ?

**AI Endpoints OVHcloud** est le cerveau de la correction : on lui envoie le rapport de failles et le fichier de configuration actuel, il renvoie le fichier corrigé avec une explication en français. Son API parle le même langage que celle d'OpenAI, donc les outils standards fonctionnent directement.

**Le remédiateur** (`apps/remediator/`) est la brique qu'on a développée nous-mêmes : un script Python qui fait le lien entre tout le reste. Il lit un rapport de sécurité, interroge l'IA, récupère le fichier corrigé, puis crée une branche sur GitHub, committe la correction et ouvre une Pull Request — automatiquement. On l'a testé en conditions réelles : une PR générée par l'IA a corrigé notre application vulnérable (image de 2018 remplacée, mode privilégié supprimé, utilisateur non-root, limites ajoutées), elle a été relue et mergée par l'équipe, et Argo CD a appliqué le tout sans intervention.

## 3. Choix techniques et pourquoi

**Trivy plutôt que Kubescape** : le brief laissait le choix. Trivy stocke ses rapports directement dans le cluster, dans un format qu'un script Python lit nativement — pas besoin d'outil supplémentaire ni de conversion.

**Kyverno en mode signalement** : choix pragmatique expliqué plus haut — on garde une démo fonctionnelle, et on sait qu'en production réelle on passerait les règles en mode blocage une fois l'application assainie.

**Une API compatible OpenAI pour l'IA** : plutôt que d'écrire du code spécifique à OVHcloud, on profite du format standard. Résultat : le même code marcherait avec n'importe quel fournisseur, et les tests sont simples.

**La revue humaine avant merge, non négociable** : c'est le garde-fou de toute la chaîne. Une IA peut proposer un fichier invalide ou une image qui n'existe pas — c'est exactement le rôle de la relecture humaine de rattraper ça avant que ça parte en production.

**Argo Rollouts pour limiter le risque du correctif** : une correction de vulnérabilité peut remplacer une image, changer un `securityContext` ou modifier des ressources. Même si le correctif est bon côté sécurité, il peut introduire un problème applicatif. Argo Rollouts permet donc de déployer la correction progressivement et de revenir automatiquement à la version précédente si les signaux d'observabilité ne sont pas bons.

Le flux de déploiement sécurisé devient :

```
Pull Request validée
        │
        ▼
Merge dans Git
        │
        ▼
Argo CD synchronise le manifeste
        │
        ▼
Argo Rollouts déploie progressivement
        │
        ▼
Métriques / logs observés
        │
        ├── OK → promotion de la nouvelle version
        │
        └── KO → rollback vers la version précédente
```

**Fluent Bit + Loki plutôt qu'un stockage de logs lourd** : on voulait une brique rapide à déployer, adaptée à Kubernetes et facile à démontrer. Fluent Bit est léger et standard pour la collecte. Loki évite d'indexer tout le contenu des logs : il indexe surtout les labels, ce qui correspond bien à Kubernetes (`namespace`, `pod`, `container`). Grafana étant déjà présent pour les métriques, l'intégration des logs dans la même interface est naturelle.

Le flux de logs est donc :

```
Pods Kubernetes
        │
        ▼
Logs stdout/stderr
        │
        ▼
Fluent Bit sur chaque nœud
        │
        ▼
Loki
        │
        ▼
Grafana / LogQL
```

## 4. Limites et pistes d'amélioration

Aujourd'hui, le remédiateur lit le rapport de sécurité depuis un fichier qu'on lui donne, plutôt que d'aller le chercher tout seul dans le cluster. La prochaine étape logique, c'est de le faire tourner en tâche planifiée dans le cluster, entièrement autonome.

On ne vérifie pas non plus automatiquement que le fichier proposé par l'IA est déployable avant d'ouvrir la PR — aujourd'hui, c'est la relecture humaine qui joue ce rôle. Et nos clés d'accès (GitHub, IA) sont encore stockées sur les postes des développeurs plutôt que gérées proprement dans le cluster avec un outil dédié comme External Secrets Operator, la brique optionnelle du brief.

Enfin, la démo repose sur une seule application cible : étendre le remédiateur à tous les workloads du cluster demanderait de boucler sur l'ensemble des rapports, ce qui est prévu dans la structure du code mais pas encore branché.

À noter, en toute transparence : Grafana Loki (utilisé pour les logs) n'est pas un projet hébergé par la CNCF, contrairement au reste de la stack. On l'assume comme une brique bonus, au même titre qu'AI Endpoints OVHcloud — voir le tableau ci-dessous.

## 5. Tableau récapitulatif du statut CNCF

| Composant | Rôle dans la chaîne | Statut CNCF |
|---|---|---|
| Argo CD | GitOps — synchronisation Git → cluster | Graduated |
| Trivy-operator | Audit de sécurité (CVE + config) | Projet Aqua Security, scanner validé CNCF |
| Kyverno | Policy-as-code | Graduated |
| Falco | Détection de menaces runtime | Graduated |
| Prometheus | Observabilité & métriques | Graduated |
| AI Endpoints | Couche d'IA générative | OVHcloud (hors CNCF — assumé dans le brief) |
| Argo Rollouts | Déploiements progressifs (bonus) | Graduated (projet Argo) |
| Fluent Bit | Collecte de logs (bonus) | Graduated (projet Fluent) |
| Grafana Loki | Agrégation de logs (bonus) | Hors CNCF — projet Grafana Labs, assumé comme brique bonus |
