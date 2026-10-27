// CLI de l'édition libre (MIT) : SBOM, vulnérabilités, triage, VEX et garde-fou CI.
// Les signalements de l'article 14, les exigences, le dossier technique, le tableau de bord
// et les gabarits font partie de l'édition complète.
import path from 'node:path';
import { NOM_CONFIG, modeleConfig, chargerConfig, ecrireJson, lireJson, ErreurConfig } from './config.js';
import { analyserArgs, texte, Sortie, sbom, scan, triage, vex, fichiers } from './base.js';
import { enrichir, registreVide } from './triage.js';
import { verifier, formater } from './verifier.js';
import { VERSION_OUTIL } from './version-outil.js';
import fs from 'node:fs';

export const AIDE = `consigne-cra ${VERSION_OUTIL} (édition libre, MIT) — inventaire et vulnérabilités pour le Cyber Resilience Act

Usage : cra <commande> [options]

  init [--nom <produit>]          Crée cra.config.json
  sbom                            SBOM CycloneDX 1.6 (cra-sortie/sbom.cdx.json)
  scan [--hors-ligne <chemin>]... [--kev <fichier>] [--sans-kev]
                                  Vulnérabilités OSV (en ligne ou hors ligne) et exploitation active (CISA KEV)
  triage [<ID> --statut <s> ...]  Décisions d'analyse (VEX)
  vex                             Export CycloneDX, OpenVEX, CSAF 2.0
  verifier [--seuil <gravité>] [--format texte|json|github]   Garde-fou CI

Édition complète : échéances et brouillons de signalement (art. 14), exigences de l'annexe I,
dossier technique de l'annexe VII, tableau de bord, gabarits (procédure, politique, security.txt).`;

export async function executer(argv, deps = {}) {
  const d = { cwd: process.cwd(), fetch: globalThis.fetch, maintenant: new Date(), ...deps };
  const out = deps.sortie || new Sortie();
  const { pos, opt } = analyserArgs(argv);
  const [commande, ...reste] = pos;
  try {
    if (!commande || commande === 'aide' || opt.aide || opt.help) { out.ecrire(AIDE); return 0; }
    if (commande === 'version' || opt.version) { out.ecrire(VERSION_OUTIL); return 0; }
    if (commande === 'init') {
      const chemin = path.resolve(d.cwd, texte(opt.config) || NOM_CONFIG);
      if (fs.existsSync(chemin)) out.ecrire(`${path.basename(chemin)} existe déjà : conservé.`);
      else { ecrireJson(chemin, modeleConfig(texte(opt.nom) || path.basename(path.dirname(chemin)))); out.ecrire(`Créé : ${path.basename(chemin)}`); }
      return 0;
    }
    const cfg = chargerConfig(path.resolve(d.cwd, texte(opt.config) || NOM_CONFIG));
    switch (commande) {
      case 'sbom': sbom(cfg, out, d.maintenant); return 0;
      case 'scan': await scan(cfg, opt, out, d); return 0;
      case 'triage': triage(cfg, reste, opt, out, d.maintenant); return 0;
      case 'vex': vex(cfg, out, d.maintenant); return 0;
      case 'verifier': {
        const f = fichiers(cfg);
        const scanRes = lireJson(f.scan, null);
        const etat = { cfg, maintenant: d.maintenant, incidents: [], bom: lireJson(f.sbom, null), scan: scanRes, constats: scanRes ? enrichir(scanRes.constats, lireJson(f.triage, registreVide())) : [] };
        const r = verifier(etat, { seuil: texte(opt.seuil) || 'haute' });
        out.ecrire(formater(r, texte(opt.format) || 'texte'));
        return r.ok ? 0 : 1;
      }
      default:
        out.erreur(['incident', 'exigence', 'exigences', 'dossier', 'tableau', 'gabarits', 'tout'].includes(commande)
          ? `« ${commande} » fait partie de l'édition complète de consigne-cra.`
          : `Commande inconnue : ${commande}. « cra aide » pour la liste.`);
        return 2;
    }
  } catch (e) {
    out.erreur(e instanceof ErreurConfig ? e.message : `Erreur : ${e.message}`);
    return 2;
  }
}
