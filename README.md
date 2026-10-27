# consigne-cra — édition libre

SBOM CycloneDX, vulnérabilités OSV, exploitation active (CISA KEV), triage VEX et garde-fou d'intégration continue. En local, hors ligne si besoin, sans aucune dépendance d'exécution. Licence MIT.

Pensé pour les fabricants et éditeurs qui préparent le Cyber Resilience Act (règlement (UE) 2024/2847) et ne veulent pas envoyer leur code dans un service tiers.

## Installation

Node.js 20 ou plus récent.

```sh
git clone <ce dépôt> consigne-cra-libre
npm install -g ./consigne-cra-libre
cra version
```

## Utilisation

```sh
cd mon-produit
cra init --nom "Mon produit"      # puis complétez cra.config.json
cra sbom                          # cra-sortie/sbom.cdx.json (CycloneDX 1.6)
cra scan                          # OSV + KEV ; --hors-ligne <all.zip> --kev <fichier> sur réseau isolé
cra triage                        # constats sans décision
cra triage GHSA-xxxx --statut non_affecte --justification code_not_reachable --detail "…"
cra vex                           # vex.cdx.json, vex.openvex.json, vex.csaf.json
cra verifier --format github      # code de sortie 1 si une vulnérabilité exploitée n'est pas traitée
```

Démonstration hors ligne (données OSV et KEV réelles, produit fictif) :

```sh
cd demo/passerelle-atelier
cra sbom && cra scan --hors-ligne ../base-osv --kev ../kev-extrait.json && cra verifier
```

Écosystèmes : npm (package-lock, yarn, pnpm), NuGet (packages.lock.json), PyPI (requirements.txt, poetry.lock), Cargo, Go, Composer ; import de SBOM CycloneDX ou SPDX JSON pour le micrologiciel et le reste.

## Ce qui sort de votre poste

En ligne : les purl (nom et version des paquets tiers) vers api.osv.dev et le téléchargement du catalogue KEV. Rien en mode `--hors-ligne`.

## Édition complète

L'édition complète ajoute ce que le règlement demande au-delà de l'inventaire :

* registre des signalements de l'article 14 avec échéances 24 h / 72 h / rapport final et brouillons ;
* exigences essentielles de l'annexe I avec preuves, contrôle de l'annexe II ;
* dossier technique de l'annexe VII imprimable et projet de déclaration UE de conformité ;
* tableau de bord HTML ;
* gabarits : procédure interne de signalement, politique de divulgation coordonnée et security.txt, analyse de risques reliée à l'annexe I.

## Avertissement

Outil d'organisation et de preuves. Ce n'est ni un avis juridique, ni une évaluation de conformité. Les données de vulnérabilités proviennent d'OSV et de la CISA et peuvent être incomplètes.
