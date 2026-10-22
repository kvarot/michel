# VulnPilot — Politique de souveraineté, IA locale et traçabilité des données sensibles

> Document d'origine fourni par Kévin Varot le 2026-10-22. Fait autorité sur le design (`docs/superpowers/specs/2026-10-22-vulnpilot-design.md`). Les fichiers `docs/security/*.md` listés en § 14 en dérivent.

**Statut :** exigence architecturale obligatoire
**Priorité :** critique
**Mode IA par défaut :** modèle local
**Classification par défaut :** données sensibles
**Philosophie :** local-first, privacy by design, sécurité vérifiable et open source
**Application :** backend, frontend PWA, agent local, scanners, workers, stockage, journaux, modèles IA et intégrations externes.

---

# 1. Objectifs et principes fondamentaux

VulnPilot est une plateforme open source de détection et de correction des vulnérabilités logicielles. Elle peut manipuler du code propriétaire, des fichiers de configuration, des dépendances, des secrets potentiels, des rapports de sécurité et des informations sur l'infrastructure.

Ces informations doivent être considérées comme sensibles par défaut.

L'architecture doit respecter les principes suivants :

1. **IA locale par défaut :** les prompts, le contexte et le code restent dans l'environnement contrôlé.
2. **Aucune sortie réseau non autorisée :** les communications sortantes sont bloquées par défaut et autorisées explicitement.
3. **Pas de dépendance à un fournisseur IA :** aucune API externe n'est nécessaire au fonctionnement du cœur de VulnPilot.
4. **Traçabilité de bout en bout :** chaque analyse et chaque correction doit être reliée à ses entrées, son modèle, ses instructions, ses outils, ses résultats et ses validations.
5. **Confidentialité des journaux :** la traçabilité ne doit pas devenir une source supplémentaire de fuite.
6. **Contrôle humain :** l'IA propose et exécute dans un environnement isolé, mais ne déploie jamais automatiquement en production.
7. **Preuves vérifiables :** ne jamais déclarer une analyse, une correction ou un contrôle réussi sans résultat observable.
8. **Open source :** le mécanisme de souveraineté, ses politiques et ses contrôles doivent faire partie du dépôt public.
9. **Mode hors ligne :** les fonctions compatibles doivent fonctionner sans accès Internet, avec indication explicite de la fraîcheur des données.
10. **Séparation des responsabilités :** le modèle IA n'est pas l'autorité chargée de décider seul si une opération sensible est autorisée.

Toute dérogation à ces principes doit être explicite, limitée, documentée et journalisée.

# 2. Modèle de menace

VulnPilot doit se protéger contre les risques suivants :

- fuite de code source ou de secrets vers un fournisseur externe ;
- connexion réseau inattendue d'un composant ;
- envoi de données via la télémétrie d'une dépendance ;
- prompt injection contenue dans un dépôt, un README, une issue ou un rapport de vulnérabilité ;
- exécution de commandes dangereuses proposées par un modèle ;
- altération ou suppression des journaux d'audit ;
- accès non autorisé aux prompts et résultats archivés ;
- confusion entre une vulnérabilité détectée, une correction proposée et une correction réellement validée ;
- utilisation d'un modèle ou d'une version non autorisés ;
- téléchargement ou remplacement non contrôlé d'un modèle ;
- compromission de l'agent local ;
- fuite de données à travers les notifications, exports, logs ou rapports ;
- reprise d'une tâche interrompue avec un contexte incorrect ;
- présentation trompeuse d'un environnement comme étant souverain ou conforme HDS.

Le modèle de menace et les contrôles doivent être documentés dans `docs/security/threat-model.md`.

# 3. Architecture de confiance

Séparer les composants selon leurs responsabilités et leurs niveaux de confiance.

## 3.1 Composants

- **PWA :** interface de consultation et de pilotage.
- **API VulnPilot :** authentification, autorisations, politiques et orchestration.
- **Base de données :** projets, vulnérabilités, tâches, configurations et historiques.
- **Journal d'audit :** événements de sécurité et de gouvernance.
- **Agent local :** accès contrôlé aux projets et exécution des outils autorisés.
- **Moteur de modèles :** exécution locale de l'inférence IA.
- **Workers de scan :** exécution isolée des scanners.
- **Workers de correction :** application des modifications dans des environnements temporaires.
- **Gestionnaire de politiques :** autorisation des opérations, fournisseurs, modèles et flux réseau.
- **Gestionnaire de notifications :** transmission des alertes autorisées.

Le modèle IA ne doit jamais pouvoir modifier directement les politiques de sécurité, les permissions des utilisateurs, les règles réseau ou les journaux d'audit.

## 3.2 Flux de données

Le flux normal de correction doit suivre cet ordre :

1. Le scanner produit des résultats.
2. Le backend normalise les résultats et identifie les données sensibles.
3. Le gestionnaire de politiques vérifie les autorisations.
4. Le contexte nécessaire est préparé et minimisé.
5. Le prompt et son manifeste sont enregistrés selon la politique d'audit.
6. Le modèle local reçoit uniquement les données autorisées.
7. La réponse est contrôlée et transformée en proposition de modification.
8. Le correctif est appliqué dans un environnement isolé.
9. Les tests et le nouveau scan sont exécutés.
10. Les preuves, les résultats et les empreintes sont enregistrés.
11. Une approbation humaine est demandée lorsque la politique l'exige.
12. La tâche est clôturée sans déploiement automatique en production.

Chaque étape doit avoir un identifiant de corrélation commun et des événements d'audit distincts.

# 4. Mode local strict

Créer un mode nommé `strict_local`.

Il doit être activé par défaut lors d'une installation destinée aux données sensibles.

Configuration indicative :

```yaml
sovereignty:
  mode: strict_local
  data_classification: sensitive

  ai:
    provider_policy: local_only
    external_providers_enabled: false
    model_downloads_enabled: false
    automatic_model_updates: false

  network:
    default_egress: deny
    telemetry_enabled: false
    remote_error_reporting: false

  audit:
    enabled: true
    integrity_protection: required
    prompt_content_retention: encrypted_configurable

  remediation:
    isolated_execution_required: true
    production_deployment_allowed: false
    human_approval_required_for_merge: true
```

Ce fichier constitue une configuration initiale illustrative. Le schéma réel doit être validé par le backend, versionné et documenté.

## 4.1 Comportement obligatoire

En mode `strict_local` :

- aucune API IA externe ne peut être appelée ;
- aucun code source ne peut être envoyé à un service tiers ;
- aucun appel d'analytique ou de télémétrie n'est effectué ;
- aucune erreur n'est transmise automatiquement à un service distant ;
- aucune dépendance n'est téléchargée automatiquement ;
- aucun modèle n'est remplacé automatiquement ;
- les opérations exigeant Internet échouent de manière explicite ;
- les données et résultats locaux restent consultables ;
- l'utilisateur peut exporter les rapports vers une destination autorisée.

Le contrôle ne doit pas dépendre uniquement d'une variable d'environnement ou d'une condition dans le frontend. Il doit être appliqué côté backend et, lorsque nécessaire, au niveau du système d'exploitation ou du réseau.

## 4.2 Contrôle effectif des flux réseau

Mettre en place plusieurs niveaux complémentaires :

1. Liste d'autorisation des destinations et opérations réseau.
2. Contrôle des sorties réseau au niveau des conteneurs ou de l'hôte.
3. Séparation des workers qui ont besoin d'Internet et de ceux qui n'en ont pas besoin.
4. Journaux des tentatives de connexion autorisées ou refusées.
5. Tests automatiques vérifiant l'absence de trafic externe non autorisé.
6. Documentation des communications requises par chaque dépendance.

Ne pas considérer le mode hors ligne comme garanti uniquement parce que le code n'utilise pas volontairement d'API externe.

Pour les installations sensibles, fournir un profil Docker ou une procédure système qui interdit réellement les sorties réseau des composants IA et de correction.

L'interface doit signaler toute configuration qui ne permet pas de garantir cette isolation.

# 5. Gestion des modèles IA

## 5.1 Architecture indépendante du fournisseur

Créer une interface commune, par exemple `ModelProvider`, comprenant des opérations contrôlées :

- `get_model_metadata()`
- `check_availability()`
- `generate()`
- `cancel()`
- `health_check()`

Les signatures réelles doivent être définies dans le code et testées.

Prévoir des adaptateurs séparés pour :

- un moteur local compatible avec des modèles à poids ouverts ;
- un moteur local alternatif ;
- d'éventuels fournisseurs externes, désactivés par défaut.

Les appels aux modèles doivent tous passer par la passerelle IA de VulnPilot. Aucun autre composant ne doit pouvoir appeler directement une API de modèle.

## 5.2 Registre des modèles

Chaque modèle autorisé doit avoir une fiche comprenant :

- nom ;
- identifiant exact ;
- version ou révision ;
- empreinte cryptographique des fichiers ;
- format et quantification, le cas échéant ;
- licence et conditions d'utilisation ;
- origine du modèle ;
- date d'installation ;
- date de dernière vérification ;
- capacités et limites connues ;
- contraintes matérielles ;
- statut d'approbation.

Refuser les modèles inconnus lorsque le mode strict est actif.

Un modèle téléchargé doit être vérifié avant utilisation. Les mises à jour nécessitent une action explicite et une nouvelle validation.

Ne pas supposer que tous les modèles à poids ouverts autorisent les mêmes usages ou la redistribution.

## 5.3 Installation des modèles

Les modèles ne doivent pas être téléchargés silencieusement au premier lancement.

Prévoir une procédure explicite permettant :

- de choisir un modèle compatible ;
- de consulter sa licence et sa provenance ;
- de télécharger ses fichiers pendant une phase d'approvisionnement contrôlée ;
- de vérifier les empreintes ;
- de valider les fichiers ;
- d'installer le modèle ;
- de vérifier son fonctionnement hors ligne.

L'installation initiale doit pouvoir être réalisée dans un environnement connecté, puis transférée dans un environnement isolé par un processus documenté.

Ne pas considérer l'inférence locale comme une garantie absolue de confidentialité : les logs, les fichiers temporaires, la mémoire, les sauvegardes, les outils et les administrateurs restent des surfaces de risque.

# 6. Traçabilité des prompts et des exécutions

Chaque appel au modèle doit être représenté par une exécution identifiable et auditable.

## 6.1 Identifiants

Créer un identifiant unique pour :

- la tâche métier ;
- l'exécution IA ;
- le prompt assemblé ;
- l'appel au modèle ;
- les appels d'outils ;
- la tentative de correction ;
- le diff produit ;
- chaque exécution de tests ;
- l'approbation finale.

Utiliser des identifiants de corrélation afin de reconstituer l'ensemble du parcours.

## 6.2 Métadonnées obligatoires

Enregistrer au minimum :

- date et heure UTC ;
- utilisateur ou service à l'origine de la tâche ;
- projet et agent concernés ;
- type de tâche ;
- fournisseur et modèle exacts ;
- révision du modèle si disponible ;
- version du moteur d'inférence ;
- version de VulnPilot ;
- version du template de prompt ;
- empreinte du prompt assemblé ;
- manifeste du contexte transmis ;
- références des vulnérabilités ;
- outils invoqués et arguments autorisés ;
- statut et durée de l'appel ;
- empreinte de la réponse conservée ;
- empreinte du patch ;
- résultats des tests ;
- résultat du nouveau scan ;
- décision d'approbation ou de rejet.

Les données inconnues doivent être explicitement signalées comme indisponibles, et non inventées.

## 6.3 Versionnement des prompts

Gérer les templates de prompts comme du code versionné.

Chaque template doit comporter :

- un identifiant stable ;
- une version ;
- un objectif ;
- les variables attendues ;
- les règles de sécurité ;
- les données autorisées ;
- les outils accessibles ;
- les tests associés ;
- un historique de modifications.

Lors d'une exécution, enregistrer l'empreinte du prompt assemblé ainsi que les versions des templates utilisées.

Pour une reproduction fiable, conserver également les paramètres pertinents et les références du contexte. Un hash seul ne permet pas de reconstituer le contenu initial.

La reproductibilité exacte des réponses n'est pas garantie pour tous les modèles, notamment si l'inférence est non déterministe.

## 6.4 Contenu des prompts

Prévoir deux politiques configurables :

**Politique standard :**
- version et empreinte des prompts ;
- métadonnées de traitement ;
- références vers les données utilisées ;
- empreintes des entrées et sorties ;
- pas d'archivage systématique des contenus sensibles.

**Politique audit renforcé :**
- conservation chiffrée des prompts et réponses complets ;
- accès limité à des rôles autorisés ;
- journalisation de chaque consultation ;
- rétention configurable ;
- export contrôlé ;
- suppression selon la politique applicable.

Avant l'archivage, détecter et masquer les secrets lorsque cela est possible. Conserver une trace du filtrage sans recopier la valeur secrète dans les logs.

Ne jamais journaliser les mots de passe, clés privées, jetons d'accès ou clés API en clair.

# 7. Intégrité des journaux et preuves d'audit

Créer un service d'audit séparé des journaux techniques ordinaires.

Chaque événement doit comporter :

- un identifiant ;
- un horodatage ;
- un acteur ;
- une action ;
- une cible ;
- un résultat ;
- un identifiant de corrélation ;
- les références aux preuves ;
- l'empreinte de l'événement précédent ou un mécanisme d'intégrité équivalent.

Prévoir des checkpoints signés et des sauvegardes protégées contre les altérations.

L'application ne doit pas permettre à un utilisateur standard ni au modèle IA de modifier ou supprimer directement les événements d'audit.

La suppression de données personnelles ou sensibles doit suivre une politique documentée. Les mécanismes de conservation des preuves doivent être conçus de manière à ne pas empêcher les suppressions légalement requises.

Les logs techniques, les logs d'audit et les contenus archivés des prompts doivent avoir des politiques de rétention distinctes.

L'interface doit permettre de filtrer les événements par projet, utilisateur, vulnérabilité, exécution IA et correction.

Prévoir un export lisible et un format structuré documenté, accompagné des empreintes nécessaires à la vérification.

Un journal chaîné par hash rend certaines altérations détectables, mais ne garantit pas à lui seul l'absence de falsification. Les clés de signature, les droits d'administration et les sauvegardes doivent être protégés séparément.

# 8. Traitement des données sensibles

Créer un registre de classification des données.

Catégories initiales :

- publique ;
- interne ;
- confidentielle ;
- sensible ;
- données de santé, si applicables.

Chaque catégorie doit définir :

- les destinations autorisées ;
- les modèles autorisés ;
- les durées de conservation ;
- les rôles autorisés ;
- les conditions d'export ;
- les obligations de chiffrement ;
- les règles de journalisation.

En mode sensible :

- minimiser le contexte transmis au modèle ;
- ne fournir que les fichiers nécessaires ;
- exclure les fichiers de secrets et les répertoires non pertinents ;
- détecter les clés et jetons potentiels ;
- contrôler les chemins ;
- limiter la taille des entrées ;
- éviter de copier inutilement les dépôts entiers ;
- chiffrer les contenus sensibles conservés ;
- séparer les données des différents projets et organisations.

La détection automatique des secrets n'est jamais parfaite. L'utilisateur doit pouvoir définir des exclusions et des règles spécifiques.

# 9. Résistance aux prompt injections

Tout contenu issu d'un dépôt, d'un fichier de configuration, d'un README, d'une issue, d'un rapport externe ou d'un résultat de scanner doit être considéré comme une donnée non fiable.

Ces contenus ne doivent jamais pouvoir remplacer les instructions système ni accorder de nouveaux privilèges au modèle.

Le modèle doit être explicitement informé de cette distinction, mais les instructions textuelles seules ne suffisent pas.

Les contrôles techniques doivent garantir que :

- les permissions sont définies hors du modèle ;
- les outils disponibles sont limités par une liste d'autorisation ;
- les arguments des outils sont validés ;
- les commandes arbitraires ne sont pas exécutées directement ;
- les accès réseau restent contrôlés indépendamment ;
- les secrets ne sont pas accessibles par défaut ;
- les opérations destructrices exigent une approbation appropriée.

Le modèle ne doit jamais être l'autorité finale pour décider qu'une commande est sûre.

# 10. Politique de correction et de validation

La correction automatique doit être progressive et contrôlée.

## Niveaux

- **Niveau 0 :** analyse et rapport uniquement.
- **Niveau 1 :** proposition de correctif.
- **Niveau 2 :** application dans un environnement isolé et exécution des tests autorisés.
- **Niveau 3 :** validation automatique des résultats, avec approbation humaine avant fusion.

Le niveau doit être défini par projet et ne doit pas pouvoir être augmenté par une réponse du modèle.

## Validation obligatoire

Une correction n'est validée que si :

1. le diff est disponible et lié à la tâche ;
2. les tests requis ont réellement été exécutés ;
3. leurs résultats sont enregistrés ;
4. le nouveau scan a été exécuté lorsque pertinent ;
5. les résultats résiduels sont documentés ;
6. les erreurs et limites sont visibles ;
7. l'approbation requise a été obtenue.

Un test non exécuté doit avoir le statut « non exécuté », jamais « réussi ».

Un scan sans résultat ne signifie pas automatiquement que la vulnérabilité est corrigée.

Aucune correction ne doit être fusionnée ou déployée automatiquement en production.

Prévoir l'annulation, le rejet et la suppression contrôlée des environnements temporaires.

# 11. Gouvernance et expérience utilisateur

Ajouter une page **Paramètres → Souveraineté et IA**.

Afficher clairement :

- le mode de traitement ;
- le modèle actif ;
- sa version ;
- son origine ;
- sa licence ;
- l'état de la vérification de son empreinte ;
- les données susceptibles d'être transmises ;
- les flux réseau autorisés ;
- la date de dernière vérification ;
- la politique de conservation des prompts ;
- l'état des contrôles d'audit ;
- les limites connues.

En mode strict local, afficher un état explicite indiquant que les appels IA externes sont désactivés.

Si un composant nécessite Internet, afficher la raison, la destination, les données concernées et l'action nécessaire. Ne jamais contourner automatiquement le blocage.

Tout changement de fournisseur, de modèle ou de politique doit être journalisé.

Les utilisateurs doivent pouvoir consulter l'historique des décisions IA, le diff, les tests et les preuves associées.

# 12. HDS et exigences réglementaires

VulnPilot doit être conçu pour faciliter les déploiements soumis à des exigences élevées de confidentialité, d'auditabilité et de maîtrise des flux.

Cependant :

- ne jamais déclarer VulnPilot certifié HDS sans preuve formelle ;
- ne pas assimiler l'exécution locale à une conformité réglementaire automatique ;
- identifier les traitements et données concernés ;
- documenter les responsabilités, sous-traitants et flux ;
- vérifier le périmètre de certification de l'hébergeur lorsque requis ;
- faire qualifier le périmètre applicable par les personnes compétentes avant la mise en production.

Prévoir une documentation permettant de constituer un dossier de preuves techniques : architecture, flux, contrôles d'accès, journaux, politiques de conservation, sauvegardes, restauration, incidents et résultats des tests.

# 13. Tests obligatoires

Créer une suite automatisée couvrant au minimum les scénarios suivants.

## Tests de flux réseau

- le mode strict local bloque les appels aux fournisseurs externes ;
- un fournisseur non autorisé ne peut pas être utilisé ;
- une dépendance ne peut pas contourner la politique réseau ;
- aucune télémétrie n'est envoyée ;
- les tentatives bloquées sont tracées sans révéler de secret ;
- les opérations exigeant Internet échouent clairement.

## Tests de modèle

- un modèle inconnu est refusé en mode strict ;
- une empreinte incorrecte bloque le chargement ;
- les changements de version sont journalisés ;
- un modèle absent produit une erreur explicite ;
- aucune bascule silencieuse vers une API distante n'est possible.

## Tests de traçabilité

- chaque exécution IA possède un identifiant unique ;
- les métadonnées obligatoires sont enregistrées ;
- le prompt assemblé est lié à sa version ;
- le diff est lié à l'exécution qui l'a produit ;
- les tests et le nouveau scan sont liés à la même tâche ;
- les événements d'audit sont ordonnés et vérifiables ;
- les modifications non autorisées du journal sont détectables ;
- les accès aux prompts archivés sont journalisés.

## Tests de confidentialité

- les secrets connus sont masqués dans les journaux ;
- les erreurs ne révèlent pas de clés ni de jetons ;
- les exports sont contrôlés et audités ;
- les données des organisations sont isolées ;
- les durées de conservation sont appliquées ;
- les contenus de prompt ne sont pas exposés aux rôles non autorisés.

## Tests de sécurité IA

- un README malveillant ne peut pas modifier les permissions ;
- une prompt injection ne peut pas activer un outil interdit ;
- le modèle ne peut pas modifier la politique réseau ;
- une commande non autorisée est rejetée ;
- un patch ne peut pas être validé si les tests requis échouent ;
- une approbation absente bloque la fusion ;
- aucun chemin d'exécution ne permet un déploiement automatique en production.

## Tests de bout en bout

Simuler une vulnérabilité, produire un rapport, générer un correctif, exécuter les tests, relancer le scan, vérifier les événements d'audit et afficher l'état final dans la PWA.

Exécuter également un scénario complet sans accès Internet.

Les tests réseau doivent utiliser un environnement isolé et vérifier le trafic effectif, et pas seulement la configuration déclarée.

# 14. Documentation et fichiers à créer

Créer ou mettre à jour :

- `VULNPILOT.md`
- `docs/security/sovereignty.md`
- `docs/security/data-classification.md`
- `docs/security/threat-model.md`
- `docs/security/audit-trail.md`
- `docs/security/prompt-traceability.md`
- `docs/security/network-egress.md`
- `docs/security/ai-provider-policy.md`
- `docs/security/hds-readiness.md`
- `docs/operations/offline-installation.md`
- `docs/operations/model-provisioning.md`
- `docs/operations/backup-and-restore.md`

La documentation doit distinguer les fonctions implémentées, les contrôles testés, les contrôles déclaratifs et les travaux restant à faire.

# 15. Critères d'acceptation

Cette politique est considérée comme implémentée uniquement si :

1. L'installation utilise un modèle local ou indique clairement qu'aucun modèle n'est configuré.
2. Les appels IA externes sont désactivés par défaut.
3. Le mode strict local bloque effectivement les flux non autorisés.
4. Le modèle et sa version sont identifiables.
5. Les prompts sont versionnés et liés aux tâches.
6. Les exécutions disposent d'une traçabilité exploitable.
7. Les secrets ne sont pas enregistrés en clair dans les journaux.
8. Les données archivées sont protégées et soumises à une rétention documentée.
9. Les corrections sont isolées et testées.
10. Les décisions d'approbation sont journalisées.
11. Les contrôles réseau et d'intégrité disposent de tests automatisés.
12. Un parcours complet peut être exécuté hors ligne.
13. La documentation permet à un administrateur de comprendre les flux et les limites.
14. Aucune conformité HDS n'est revendiquée sans justification formelle.

# 16. Instructions de développement

Inspecter l'architecture existante avant toute modification.

Implémenter ces exigences par étapes, sans simuler les contrôles manquants.

Priorité de réalisation :

1. politique de configuration et refus par défaut ;
2. passerelle IA et registre des modèles ;
3. contrôles des flux réseau ;
4. journal d'audit ;
5. traçabilité des prompts ;
6. classification et protection des données ;
7. validations des corrections ;
8. interface de souveraineté ;
9. tests de sécurité ;
10. documentation et preuves.

Après chaque étape, exécuter les tests pertinents et indiquer les résultats réels.

Ne jamais présenter une configuration comme une garantie de sécurité si le contrôle correspondant n'est pas appliqué techniquement.

**Objectif final :** faire de la souveraineté, de la confidentialité et de la traçabilité des propriétés vérifiables de VulnPilot, et non de simples promesses commerciales.
