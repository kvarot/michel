# Michel — catalogue de sources de vulnérabilités (entrée du plan « sources »)

**Date :** 2026-10-23. **Origine :** liste fournie par Kévin, classée par Claude en quatre sortes. Document d'entrée du plan « sources », pas encore un design.

**Sortes :**
1. **Base** : lisible par machine, avec paquets et versions touchées ; crée des failles par comparaison avec l'inventaire (lockfiles, plus tard paquets du serveur).
2. **Enrichissement** : indexé par CVE ; ajoute des signaux aux failles existantes (exploitée, probabilité, score).
3. **Veille** : bulletin d'éditeur (page, RSS/Atom, avis GitHub d'un dépôt) ; rubrique « À lire » filtrée par les technologies déclarées ; ne crée pas de faille tant que la version installée n'est pas connue.
4. **Hors registre** : outil à brancher (plugin, export) ou référence documentaire.

5. **Plugin** : outil externe qui produit des findings (Trivy, ZAP, CodeQL en SARIF…) branché par l'interface « source de findings » ; ses résultats entrent dans le même digest et les mêmes décisions.
6. **Skill pour l'IA de codage** : consignes et outils chargés par Claude Code (ou une autre IA) quand elle corrige à partir d'un brief de Michel ; ne fournit pas de données à Michel.

« Déjà couvert » = la donnée arrive déjà par une autre source du catalogue (en général OSV).

## Principe (demande de Kévin, 2026-10-23)

Tout ce catalogue est un **registre unique que l'utilisateur gère simplement** : page « Sources » de la PWA et `michel source list|add|remove|reset|update`. Pour chaque entrée : activer, désactiver, retirer, réinitialiser au catalogue par défaut, voir la dernière lecture. Ajouter une entrée perso est possible pour toute sorte que Michel sait lire (base au format OSV, flux RSS/Atom, avis GitHub d'un dépôt, sortie SARIF ou JSON d'un plugin, dépôt de skill).

Règles communes : chaque entrée qui touche le réseau est une destination montrée en clair (« Michel va contacter X, rien de tes projets ne part ») et ajoutée à l'allowlist seulement après accord ; chaque lecture est journalisée ; rien n'est actif en `strict_local` sans accord.

Règles propres aux skills (code tiers qui s'exécute avec les droits de l'utilisateur) :
- installation seulement sur action de l'utilisateur, jamais par défaut ;
- version épinglée (commit précis), contenu montré avant installation, licence affichée ;
- mise à jour jamais automatique : Michel montre ce qui change et l'utilisateur valide ;
- installés dans `~/.claude/skills/` (jamais dans un projet scanné), retirés proprement par `michel source remove` ;
- une note de confiance affichée (auteur connu, suivi du dépôt) sans bloquer le choix de l'utilisateur.

## Général

| Source | URL | Sorte | Note |
|---|---|---|---|
| CVE.org | https://www.cve.org/ | 4 | Identifiants seulement ; déjà présents en alias dans OSV. |
| NVD (NIST) | https://nvd.nist.gov/ | 2 | Optionnel : CVSS/CPE manquants ; API lente et limitée en débit. |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 2 | Prioritaire : exploitation connue. Flux JSON quotidien. |
| CISA Vulnrichment | https://github.com/cisagov/vulnrichment | 2 | Enrichissement CVE (SSVC, CVSS, CWE). |
| OSV | https://osv.dev/ | 1 | Utilisé (Packagist, npm). Une source par écosystème. |
| GitHub Advisory Database | https://github.com/advisories | 1 | Déjà couvert : importé dans OSV (GHSA-…). |
| FIRST EPSS | https://www.first.org/epss/ | 2 | Probabilité d'exploitation, fichier quotidien. |
| Vulnerability-Lookup (CIRCL) | https://vulnerability.circl.lu/ | 2 | Agrégateur européen ; alternative ou miroir, utile en contexte HDS. |

## Mobile

| Source | URL | Sorte | Note |
|---|---|---|---|
| Android Security Bulletins | https://source.android.com/docs/security/bulletin | 3 | |
| Android Security & Privacy | https://developer.android.com/privacy-and-security/risks | 4 | Documentation. |
| OSV – Android | https://osv.dev/list?ecosystem=Android | 1 | Écosystème OSV. |
| Android Studio | https://developer.android.com/studio | 4 | Outil. |
| Apple Security Releases | https://support.apple.com/en-us/100100 | 3 | |
| Apple Platform Security | https://developer.apple.com/security/ | 4 | Documentation. |
| GitHub Advisories – Swift | https://github.com/advisories?ecosystem=Swift | 1 | Déjà couvert (OSV, écosystème SwiftURL). |
| CocoaPods Security Advisories | https://github.com/CocoaPods/CocoaPods/security/advisories | 3 | Avis GitHub d'un dépôt. |

## Web

| Source | URL | Sorte | Note |
|---|---|---|---|
| nginx Security Advisories | https://nginx.org/en/security_advisories.html | 3 | Faille réelle avec le collecteur serveur. |
| Apache HTTP Server Security | https://httpd.apache.org/security/vulnerabilities_24.html | 3 | Idem. |
| PHP Security | https://www.php.net/security | 3 | Version de PHP : collecteur serveur. |
| Symfony Security | https://symfony.com/blog/category/security | 3 | Paquets Symfony déjà couverts par OSV Packagist. |
| Laravel Advisories | https://github.com/laravel/framework/security/advisories | 3 | Déjà couvert pour le paquet (OSV Packagist). |
| Node.js Vulnerability Releases | https://nodejs.org/en/blog/vulnerability | 3 | Version de Node.js : collecteur serveur et poste. |
| React Advisories | https://github.com/facebook/react/security/advisories | 3 | Déjà couvert pour le paquet (OSV npm). |
| Next.js Advisories | https://github.com/vercel/next.js/security/advisories | 3 | Idem. |
| Angular Advisories | https://github.com/angular/angular/security/advisories | 3 | Idem. |
| Vue.js Advisories | https://github.com/vuejs/core/security/advisories | 3 | Idem. |
| WordPress Security | https://wordpress.org/news/category/security/ | 3 | |
| Drupal Security Advisories | https://www.drupal.org/security | 3 | Paquets drupal/* en partie couverts par OSV Packagist. |
| Joomla Security Centre | https://developer.joomla.org/security-centre.html | 3 | |
| Django releases / security | https://www.djangoproject.com/weblog/ | 3 | Paquet couvert par OSV PyPI si activé. |
| Flask Advisories | https://github.com/pallets/flask/security/advisories | 3 | Idem. |
| Ruby on Rails Security | https://rubyonrails.org/security | 3 | Paquets couverts par OSV RubyGems si activé. |
| ASP.NET Core Advisories | https://github.com/dotnet/aspnetcore/security/advisories | 3 | Paquets couverts par OSV NuGet si activé. |
| GitHub Advisories – npm | https://github.com/advisories?ecosystem=npm | 1 | Déjà couvert (OSV npm). |
| GitHub Advisories – Composer | https://github.com/advisories?ecosystem=composer | 1 | Déjà couvert (OSV Packagist). |
| GitHub Advisories – pip | https://github.com/advisories?ecosystem=pip | 1 | Via OSV PyPI. |
| GitHub Advisories – Maven | https://github.com/advisories?ecosystem=maven | 1 | Via OSV Maven. |
| GitHub Advisories – RubyGems | https://github.com/advisories?ecosystem=rubygems | 1 | Via OSV RubyGems. |
| GitHub Advisories – NuGet | https://github.com/advisories?ecosystem=nuget | 1 | Via OSV NuGet. |

## Infrastructure

| Source | URL | Sorte | Note |
|---|---|---|---|
| Debian Security | https://www.debian.org/security/ | 3 | Avis DSA/DLA ; données structurées via OSV Debian. |
| Debian Security Tracker | https://security-tracker.debian.org/tracker/ | 1 | Via OSV (écosystème Debian) ; utile avec le collecteur serveur HDS. |
| Ubuntu Security Notices | https://ubuntu.com/security/notices | 1 | Via OSV Ubuntu. |
| Red Hat Security | https://access.redhat.com/security/security-updates/ | 1 | Via OSV Red Hat. |
| Rocky Linux Errata | https://errata.rockylinux.org/ | 1 | Via OSV Rocky Linux. |
| AlmaLinux Errata | https://errata.almalinux.org/ | 1 | Via OSV AlmaLinux. |
| SUSE Security | https://www.suse.com/support/security/ | 1 | Via OSV SUSE / openSUSE. |
| Alpine SecDB | https://secdb.alpinelinux.org/ | 1 | Via OSV Alpine. |
| Microsoft Security Response Center | https://msrc.microsoft.com/update-guide | 3 | API CVRF possible plus tard. |
| PostgreSQL Security | https://www.postgresql.org/support/security/ | 3 | |
| Oracle Security Alerts | https://www.oracle.com/security-alerts/ | 3 | Dont MySQL. |
| MariaDB Security | https://mariadb.com/kb/en/security/ | 3 | |
| MongoDB Security | https://www.mongodb.com/docs/manual/security/ | 4 | Documentation. |
| Redis Advisories | https://github.com/redis/redis/security/advisories | 3 | Avis GitHub d'un dépôt. |
| Elastic Security | https://www.elastic.co/community/security | 3 | |
| OpenSSL Vulnerabilities | https://openssl-library.org/news/vulnerabilities/ | 3 | Paquet système : OSV distribution avec le collecteur. |
| OpenSSH Security | https://www.openssh.com/security.html | 3 | Idem. |
| WireGuard | https://www.wireguard.com/ | 4 | Site projet, pas de flux d'avis. |
| OpenVPN Security Announcements | https://community.openvpn.net/openvpn/wiki/SecurityAnnouncements | 3 | |
| HAProxy | https://www.haproxy.org/ | 4 | Site projet. |
| Traefik Advisories | https://github.com/traefik/traefik/security/advisories | 3 | Module Go couvert par OSV Go si activé. |
| Envoy Advisories | https://github.com/envoyproxy/envoy/security/advisories | 3 | |

## DevOps

| Source | URL | Sorte | Note |
|---|---|---|---|
| Docker / Moby Advisories | https://github.com/moby/moby/security/advisories | 3 | |
| containerd Advisories | https://github.com/containerd/containerd/security/advisories | 3 | |
| runc Advisories | https://github.com/opencontainers/runc/security/advisories | 3 | |
| Kubernetes Security Issues | https://kubernetes.io/docs/reference/issues-security/ | 4 | Documentation ; flux CVE officiel possible. |
| Kubernetes Advisories | https://github.com/kubernetes/kubernetes/security/advisories | 3 | |
| Helm Advisories | https://github.com/helm/helm/security/advisories | 3 | |
| Istio Advisories | https://github.com/istio/istio/security/advisories | 3 | |
| GitHub Actions Advisories | https://github.com/advisories?ecosystem=actions | 1 | Via OSV GitHub Actions, si Michel lit un jour les workflows. |
| GitLab Releases | https://about.gitlab.com/releases/categories/releases/ | 3 | |
| Jenkins Security | https://www.jenkins.io/security/ | 3 | |
| Atlassian Security Advisories | https://www.atlassian.com/trust/security/advisories | 3 | |
| Gitea Advisories | https://github.com/go-gitea/gitea/security/advisories | 3 | |
| Terraform Advisories | https://github.com/hashicorp/terraform/security/advisories | 3 | |
| Vault Advisories | https://github.com/hashicorp/vault/security/advisories | 3 | |
| Consul Advisories | https://github.com/hashicorp/consul/security/advisories | 3 | |
| Ansible Advisories | https://github.com/ansible/ansible/security/advisories | 3 | |
| Trivy Advisories | https://github.com/aquasecurity/trivy/security/advisories | 3 | |

## SecOps, observabilité, IAM

| Source | URL | Sorte | Note |
|---|---|---|---|
| Sentry Advisories | https://github.com/getsentry/sentry/security/advisories | 3 | |
| Grafana Security | https://grafana.com/security/ | 3 | |
| Prometheus Advisories | https://github.com/prometheus/prometheus/security/advisories | 3 | |
| Wazuh Advisories | https://github.com/wazuh/wazuh/security/advisories | 3 | |
| OpenSearch Security | https://opensearch.org/security.html | 3 | |
| Keycloak Security | https://www.keycloak.org/security | 3 | |
| Authentik Advisories | https://github.com/goauthentik/authentik/security/advisories | 3 | |
| OpenLDAP | https://www.openldap.org/ | 4 | Site projet. |
| OpenBao Advisories | https://github.com/openbao/openbao/security/advisories | 3 | |

## Supply chain

| Source | URL | Sorte | Note |
|---|---|---|---|
| OpenSSF | https://openssf.org/ | 4 | Organisation. |
| OpenSSF Scorecard | https://scorecard.dev/ | 4 | Outil ; signal possible plus tard (santé d'un paquet). |
| OpenSSF Malicious Packages | https://github.com/ossf/malicious-packages | 1 | Format OSV (MAL-…), repris par osv.dev : à vérifier dans les zips par écosystème. |
| deps.dev | https://deps.dev/ | 4 | Métadonnées ; déjà utilisé comme bibliothèque SemVer. |
| Snyk Vulnerability Database | https://security.snyk.io/ | exclu | Conditions d'utilisation incompatibles avec une extraction automatique. |
| FIRST CVSS | https://www.first.org/cvss/ | 4 | Standard de score. |

## Outils de veille

| Source | URL | Sorte | Note |
|---|---|---|---|
| Trivy | https://trivy.dev/ | 5 | Plugin (conteneurs, images, paquets système). |
| OWASP Dependency-Track | https://dependencytrack.org/ | 4 | Destination d'export CycloneDX + VEX, pas une source. |
| OWASP ZAP | https://www.zaproxy.org/ | 5 | Plugin (test dynamique sur une URL de test déclarée, jamais la prod par défaut). |
| CodeQL (SARIF) | https://codeql.github.com/ | 5 | Plugin d'analyse statique du code de l'utilisateur ; vérifier la licence d'usage. |
| NVD API | https://nvd.nist.gov/developers/vulnerabilities | 2 | Même source que NVD. |
| OSV API | https://google.github.io/osv.dev/api/ | 1 | Michel préfère les zips hors ligne ; l'API n'est pas nécessaire. |
| GitHub GraphQL API | https://docs.github.com/en/graphql | 3 | Moyen d'accès aux avis d'un dépôt ; jeton optionnel. |

## Skills pour l'IA de codage (sorte 6, aucun installé par défaut)

Avis du 2026-10-23 sur description seulement : dépôts non ouverts, licences à vérifier avant tout ajout au catalogue par défaut.

| Skill | Dépôt | Avis |
|---|---|---|
| Trail of Bits Code Audit (CodeQL, analyse de variantes) | trailofbits/skills | Auteur reconnu ; utile en complément du plugin CodeQL. |
| Trail of Bits YARA Rule Authoring | trailofbits/skills | Détection de logiciels malveillants ; hors usage actuel. |
| Trail of Bits Building Secure Contracts | trailofbits/skills | Smart contracts ; hors sujet. |
| Claude Code OWASP (Top 10:2025, ASVS 5.0) | agamm/claude-code-owasp | Bonnes pratiques pour l'IA qui corrige ; dépôt peu suivi, à relire. |
| Claude Agentic Framework Security | dralgorhythm/claude-agentic-framework | Menaces, revue, conformité ; dépôt très peu suivi. |
| SecSkills Pentesting Plugin | trilwu/secskills | Offensif, dépôt quasi inconnu ; non recommandé. |
| Awesome Claude Skills Security | Eyadkelleh/awesome-claude-skills-security | SecLists, CTF, bug bounty ; offensif ; non recommandé. |
| Snyk Fix | snyk/studio-recipes | Dépend du service Snyk : données envoyées à un tiers ; contraire à la politique. |
| Snyk Learning Path | snyk-labs/snyk-learning-path-skill | Dépend de Snyk Learn ; hors sujet. |

## Serveurs MCP en cybersécurité (sorte 6, aucun installé par défaut)

Relevé du 2026-10-23 à partir d'agrégateurs (étoiles approximatives, à revérifier sur GitHub). Pertinence pour Michel : **D** = défense des dépendances et du code (cœur de Michel), **S** = serveur et SIEM, **R** = rétro-ingénierie, **O** = offensif ou OSINT (hors rôle de Michel).

| Serveur MCP | Dépôt | Étoiles (≈) | Pertinence | Note |
|---|---|---|---|---|
| Semgrep | intégré au binaire semgrep (ancien semgrep/mcp, archivé) | ~670 | D | Analyse statique du code ; candidat plugin SARIF. |
| SafeDep vet | safedep/vet | ~1,1k | D | Paquets npm/PyPI vulnérables ou malveillants. |
| Mobb Vibe Shield | mobb-dev/mobb-vibe-shield-mcp | ~70 | D | Détection et correction ; vérifier s'il envoie du code à un service. |
| CVE-Search | roadwy/cve-search_mcp | ~110 | D | Interroge une instance CVE-Search ; à préférer auto-hébergée. |
| Wazuh | gbrigandi/mcp-server-wazuh | ~240 | S | Alertes SIEM ; utile avec le plan « journaux des serveurs ». |
| OPNsense | vespo92/OPNSenseMCP | ~90 | S | Pilotage de pare-feu ; écriture possible, prudence. |
| Burp Suite (officiel) | PortSwigger/mcp-server | ~780 | O | Test d'application web ; sur un environnement de test seulement. |
| IDA Pro | mrexodia/ida-pro-mcp | ~13k | R | Rétro-ingénierie. |
| GhidraMCP | LaurieWired/GhidraMCP | ~11k | R | Rétro-ingénierie. |
| JADX AI | zinja-coder/jadx-ai-mcp | ~2,9k | R | Applications Android. |
| Beelzebub | mariocandela/beelzebub | ~2,2k | S | Pot de miel, dont pièges pour agents IA. |
| SecOps MCP | securityfortech/secops-mcp | ~220 | O | Boîte à outils de pentest. |
| Shodan, VirusTotal, Maigret | BurtTheCoder/mcp-shodan, mcp-virustotal, mcp-maigret | ~150–270 | O | Services tiers : envoient des indicateurs à l'extérieur. |

Listes à suivre pour la découverte : trailofbits/skills, VoltAgent/awesome-agent-skills, travisvn/awesome-claude-skills, raphabot/awesome-cybersecurity-agentic-ai, AIM-Intelligence awesome-mcp-security (sécurité des serveurs MCP eux-mêmes : MCP-scan, MCP-Shield).

## Mise à jour quotidienne du catalogue (demande de Kévin, 2026-10-23)

Le catalogue entier se met à jour chaque jour, avant le scan du matin :
- bases et enrichissements : téléchargement des nouvelles données ;
- veille : lecture des flux, nouveautés filtrées par les technologies déclarées ;
- plugins, skills, serveurs MCP : relevé de l'état de chaque dépôt (étoiles, dernier commit, archivé ou non, nouvelle version) par l'API GitHub, jeton optionnel gardé dans le magasin de secrets ; une nouvelle version est **signalée**, jamais installée seule ;
- découverte : les dépôts les plus suivis des sujets GitHub `mcp-security`, `claude-skills` et des listes ci-dessus apparaissent dans « À découvrir », à ajouter ou ignorer par l'utilisateur ;
- le digest du matin a une ligne « catalogue » : sources mises à jour, nouvelles versions de tes skills ou serveurs MCP, nouveautés à découvrir, source injoignable.
