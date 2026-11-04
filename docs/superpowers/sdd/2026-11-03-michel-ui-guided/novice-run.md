# Essai d'un novice : les trois parcours

Plan : `docs/superpowers/plans/2026-11-03-michel-ui-guided.md`, branche `feat/ui-guided`. Ce document dit ce que l'essai a montré, ce qui a été corrigé ensuite, et ce qui reste non prouvé.

## Sur quoi l'essai a tourné

- Binaire construit avec le tag `michel_local_remote` (R33). Le service Git était un dépôt nu local. Donc pas de page de fusion et pas de lien vers le service (R19). Les liens sont couverts par les tests de 14b, pas par cet essai.
- L'agent était un faux écrit pour l'essai, hors du dépôt. Ses mots sont préparés à l'avance. Le `fakeclaude` du dépôt ne propose jamais de correction, il ne pouvait pas servir. La vraie conversation avec un agent n'a donc pas été éprouvée (R18). Le `composer update` de la correction, lui, a utilisé le réseau.
- Le serveur est un conteneur jetable, avec un systemd dégradé. L'utilisateur `michel` a reçu `sudo` sans mot de passe pour le chemin « Michel lance le script » ; ce réglage a été ajouté dans le conteneur pour l'essai.
- Le site du serveur répondait sur le port 18080 et non 8080, qui était pris par autre chose.
- `prefers-reduced-motion` a été lu dans la feuille de style seulement. Aucun navigateur ne l'a appliqué.
- Deux personnes ont joué : un « novice » (le contrôleur, qui suit un papier et note ce qu'il ressent) puis un « conducteur » qui a vérifié les étapes 3, 4 et 5 du plan, en 375 px et 1280 px, clair et sombre.

## Les trois buts du novice

| But | Résultat |
|---|---|
| 1. Voir les failles d'un projet et en corriger une | Atteint. « Vérifiée » vu dans « Problèmes résolus ». Il a fallu une aide pour la phase « accepter sur le site » (voir B3 et la demande d'aide 3). |
| 2. Contrôler un serveur et corriger sa faille | Non atteint. Il voit la faille et comment elle se règle, mais le script devait être lancé à la main en root sur le serveur. Il aurait abandonné. |
| 3. Voir ce qui est ouvert sur le serveur | Atteint. Il voit le site (normal), l'administration, et la base de données « à fermer ». Il ne sait pas comment la fermer. |

## Les chiffres du novice

- Hésitations : 8.
- Mots non compris : environ 40.
- Clics sans effet : 3.
- Demandes d'aide : 4 (la question GitHub, la fenêtre de consentement à l'IA, « le site » où accepter la correction, le script à lancer en root).

Le conducteur a compté 0 défaut critique, 1 majeur, 3 moyens et 8 mineurs.

## Ce que la personne dit

Ce qui l'a arrêtée ou gênée, dans ses mots :

- « Je ne sais pas ce que c'est » (GitHub, Bitbucket, GitLab), et le texte disait « la réponse semble être oui » : « donc je clique Oui ».
- « J'aurais demandé de l'aide » devant la fenêtre « Laisser un agent travailler ? » (strict_local, politique, IA externes, fichier .bak, packagist).
- « Deux bouts de consignes contradictoires » : « Fusionne-la puis déploie avec PhpStorm » contre un bouton « Envoyer la correction ». « PhpStorm, je ne sais pas ce que c'est ; je ne l'ai pas. »
- « Je dois donc accepter quelque chose sur un site extérieur, que je n'ai pas. »
- « Voir le détail » ouvre les 14 failles d'un coup : « déroutant ».
- « Je ne sais pas le faire (pas de terminal, je ne sais pas ce que "root" veut dire). J'aurais abandonné ici. »
- « Je n'ai pas cliqué "Je l'ai appliqué" car je ne l'ai pas fait, ce serait mentir. »
- « Je ne sais pas comment mettre en ligne. »
- « Je ne sais pas comment fermer la base de données. »

Ce qui l'a rassurée :

- « Michel ne surveille encore rien » et le bouton « Ajouter un projet » : « clair ».
- Le nom du projet qui se remplit seul : « rassurant ».
- « Contrôle en cours, tu peux quitter la page », « ça peut prendre quelques minutes ».
- « Tu peux revenir en arrière », « ton site ne change pas », « rien n'arrive dans ton code sans ton accord ».
- « Risque estimé 30 sur 100 » et « la faille a disparu ».
- L'empreinte du serveur « identique à mon papier : très rassurant ».
- « Normal, c'est ton site » et « À fermer » bien mis en avant.

## Les blocages et ce qu'ils sont devenus

Deux séries de corrections ont suivi : la première après l'essai du novice, la seconde après le passage du conducteur.

- **B1, script à lancer en root (but 2).** Cause en trois parties : rien n'annonçait que « qui lance le script » était un choix ; le réglage changé après coup ne touchait pas la fiche déjà validée ; la page disait seulement « copie et lance en root ». Corrigé : la page annonce le choix avec un lien vers les réglages, et un bouton permet de remettre la fiche validée à Michel, avec une confirmation qui parle des droits d'administrateur. Vu dans un navigateur, jusqu'à « Vérifiée ». Les refus (sudo demandé avec mot de passe, serveur injoignable) ont aussi été joués.
- **B2, « Lancer la correction » sans effet au premier clic.** Non reproduit : le conducteur a eu la fenêtre dès le premier clic à chaque essai, sur plusieurs états et plusieurs binaires. Une cause supposée a été testée et écartée. Des durcissements voisins ont été faits (un refus s'affiche maintenant en vue ; la fenêtre ne lit jamais la fiche d'un autre projet). B2 reste ouvert.
- **B3, « Mettre à jour mon dossier » sans effet, page figée.** Une cause a été reproduite : pendant l'attente, le bouton devenait bleu sur bleu, sans mot. Corrigé (le bouton garde son aspect, une phrase d'attente s'affiche, de même pour le bouton d'envoi). Le gel réel de la page n'a pas été reproduit : la cause du clic perdu du novice n'est pas établie.
- **B4, consignes contradictoires (PhpStorm).** Les messages disent seulement que la branche existe, à part du code. Plus aucun outil n'est nommé.
- **B5, fenêtre de consentement à l'IA.** Réécrite : un paragraphe simple selon le cas (projet ou serveur), les lignes de ce qui part et vers qui toujours visibles, seuls les noms techniques repliés. Le conducteur l'a relue en projet et en serveur. Le bouton dit ce qu'il fait : quitter la protection et laisser l'IA travailler. Restent dans les lignes visibles quelques mots techniques (composer, npm, noms d'hôtes) : ils sont le consentement lui-même.
- **B6, source `osv.debian` éteinte.** La fiche dit ce que donne la source, ce que l'allumer permet (un téléchargement) et mène à la page Sources.
- **B7, question GitHub.** La question explique les services ; « Je ne sais pas » est une réponse admise et expliquée ; « la réponse semble être oui » a disparu ; « rattacher » est devenu « relier ». « Dépôt local » reste (R33).
- **B8, exposition : l'administration signalée « à vérifier » à tort.** Le conteneur redirige le port, Michel ne voit pas les redirections. Règle revue : un seul service d'administration, même sur un autre numéro, est normal avec une note qui dit que c'est une déduction.
- **B9, « Voir le détail » ouvre tout.** Trois fiches d'abord, puis « Et N autres failles : les montrer ». Les failles critiques passent devant. Vu avec 11 autres failles ; cinq critiques à la suite, non vu dans un navigateur.
- **B10, « L'avis dit : … » en anglais.** Dit maintenant que c'est le texte d'origine, souvent en anglais.

Défauts trouvés par le conducteur :

- **D-1, majeur.** La correction d'un réglage php.ini finissait « la vérification voit toujours le problème » tant que la source `osv.debian` était éteinte (réglage par défaut), alors que Michel ne pouvait simplement pas juger. Cause : tout ce qui touchait un PHP installé par paquet était protégé de la fermeture. Corrigé : seuls les cas qui dépendent vraiment de cette source restent protégés ; si Michel ne peut pas juger, il le dit et nomme la source à allumer. Rejoué de bout en bout, source éteinte : les cinq étapes « fait », « Vérifiée ». La phrase « n'a pas pu juger » et son lien : testés, pas vus dans un navigateur.
- **D-2 à D-12.** Lien « Ouvrir les réglages » qui ne faisait rien (corrigé, vu) ; faille vérifiée encore dans « disparues » (corrigé en code, vu en partie) ; « Corriger » proposé sur un dossier sans Git (corrigé, vu) ; décision proposée après « Vérifiée » (corrigé, vu) ; lignes identiques, textes et casse, bouton d'étape 2 qui ne lance pas de contrôle (le libellé le dit maintenant, il ne lance toujours rien) ; mise à jour refusée sans nommer le fichier (volontaire, la phrase renvoie à `git status`, non vue dans un navigateur). La remarque de l'outil de développement « No label associated with a form field » n'est pas tranchée. La phrase « recherche impossible : les paquets… » n'a pas été réécrite.

Un rejeu après la seconde série de corrections a encore trouvé deux défauts, corrigés dans le dernier commit.

## Ce que le conducteur a vérifié

| Étape du plan | Résultat |
|---|---|
| Étape 3, parcours 1 (projet, 375 px sombre) | Réussi, avec défauts mineurs. Une seconde demande d'envoi dit « déjà sur le service ». Un fichier suivi modifié : la mise à jour refuse et ne touche à rien. Un dossier sans lien : la commande de fusion est donnée et jouée, « Vérifiée ». Un dossier sans Git : pas de question, pas de « Lancer la correction » ; un lien « Corriger » restait (défaut D-4, corrigé). |
| Étape 3, parcours 2 (serveur) | Réussi seulement après avoir allumé la source Debian (défaut D-1) ; après correction, réussi source éteinte. |
| Étape 3, parcours 3 (exposition) | Réussi. Après fermeture de la base : « Réservé au serveur » et « Plus vus ouverts à tous », sans dire « Vérifiée ». Outil de lecture des services retiré : « Michel n'a pas pu voir », jamais « rien d'ouvert ». |
| Étape 4, écrans | Réussi : aucun débordement à 375 px ni à 1280 px, aucun événement de politique de sécurité, aucune requête refusée ni vers un hôte extérieur. Clavier seul : ajout d'un projet de bout en bout, focus visible, Échap ferme les fenêtres. Dossier de données vide : tous les écrans vides ont leur texte. Le lien « aller au contenu » n'a pas été essayé. |
| Étape 5, absences | Réussi : après lecture de journaux piégés (marqueurs, noms, jeton, identifiants), aucune des 16 chaînes cherchées dans la page, les réponses de l'API, le dossier de données, le journal d'audit ni les échanges avec l'agent. L'adresse d'un dépôt portant un mot de passe n'est ni affichée ni gardée ; la carte le dit. Aucune erreur de page à la lecture des journaux. |

Après les corrections : 644 tests Vitest passés, construction du web réussie, `go test ./... -count=1` sans échec, `go vet` muet, `go test ./internal/hygiene/` vert. `gofmt -l` nomme un fichier de test que ces corrections n'ont pas touché.

## Ce qui reste non prouvé

- **B2** n'est pas reproduit. Le premier clic perdu du novice reste sans explication.
- **La cause de B3** n'est pas établie : un défaut proche a été trouvé et corrigé, le gel de la page n'a pas été vu.
- **Les vrais hôtes** : les liens vers un service Git (page de fusion) et la poussée vers un vrai service n'ont pas été essayés. Seul un dépôt nu local a servi.
- **L'agent SSH de Windows (OpenSSH)** n'a pas été essayé. L'essai a utilisé un agent de test en espace utilisateur.
- **La vraie conversation avec un agent** : les mots de l'agent étaient préparés à l'avance.
- **Plusieurs écrans** n'ont été vus qu'en tests : le bouton de reprise après un serveur injoignable, le mode « Signaler » seul, la remise à Michel d'un correctif de paquet, la fenêtre de consentement en mode avancé et en anglais, `prefers-reduced-motion` dans un vrai navigateur.
- **Un rejeu complet par un novice après les corrections n'a pas été fait.** Le conducteur a rejoué les parcours après les corrections, mais il connaît le produit. On ne sait donc pas si le novice atteindrait le but 2, ni si les mots réécrits suffisent. Il faudrait un nouvel essai avec une personne qui découvre Michel.
