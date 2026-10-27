// Fichier de configuration du produit (cra.config.json) et dossier de données (cra/).
import fs from 'node:fs';
import path from 'node:path';

export const NOM_CONFIG = 'cra.config.json';
export const CATEGORIES = ['defaut', 'classe-I', 'classe-II', 'critique'];

export function modeleConfig(nomProduit = 'Mon produit') {
  const dans5ans = new Date();
  dans5ans.setFullYear(dans5ans.getFullYear() + 5);
  return {
    produit: {
      nom: nomProduit,
      version: '1.0.0',
      type: 'logiciel',
      description: 'À compléter : ce que fait le produit, en deux phrases.',
      usagePrevu: 'À compléter : destination prévue et environnement d\'utilisation (art. 3, point 21).',
      categorie: 'defaut',
      categorieMotif: 'À compléter : pourquoi le produit ne figure pas aux annexes III et IV.',
      finSupport: dans5ans.toISOString().slice(0, 10),
      finSupportMotif: 'À compléter : durée d\'utilisation attendue par vos clients et ce qui la justifie (art. 13, § 8 : au moins cinq ans, sauf durée d\'utilisation plus courte).',
      etatsMembres: ['FR'],
      url: '',
    },
    fabricant: {
      nom: 'À compléter',
      adresse: 'À compléter',
      email: 'securite@exemple.fr',
      site: 'https://exemple.fr',
      contactVulnerabilites: 'securite@exemple.fr',
      politiqueDivulgation: 'https://exemple.fr/securite',
    },
    sources: { racine: '.', exclure: [], sbomImportees: [], inclureDev: false },
    normes: [],
    sortie: 'cra-sortie',
  };
}

export class ErreurConfig extends Error {}

export function chargerConfig(fichier) {
  const chemin = path.resolve(fichier || NOM_CONFIG);
  if (!fs.existsSync(chemin)) throw new ErreurConfig(`Configuration introuvable : ${chemin}. Lancez « cra init ».`);
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(chemin, 'utf8')); } catch (e) {
    throw new ErreurConfig(`${path.basename(chemin)} n'est pas un JSON valide : ${e.message}`);
  }
  const erreurs = validerConfig(cfg);
  if (erreurs.length) throw new ErreurConfig(`Configuration invalide :\n- ${erreurs.join('\n- ')}`);
  const base = path.dirname(chemin);
  return {
    ...cfg,
    chemin,
    base,
    racine: path.resolve(base, cfg.sources?.racine || '.'),
    dossierDonnees: path.join(base, 'cra'),
    dossierSortie: path.resolve(base, cfg.sortie || 'cra-sortie'),
  };
}

export function validerConfig(cfg) {
  const e = [];
  if (!cfg || typeof cfg !== 'object') return ['racine : objet attendu'];
  const p = cfg.produit || {};
  if (!p.nom) e.push('produit.nom est obligatoire');
  if (!p.version) e.push('produit.version est obligatoire');
  if (p.categorie && !CATEGORIES.includes(p.categorie)) e.push(`produit.categorie doit valoir ${CATEGORIES.join(', ')}`);
  if (p.finSupport && !/^\d{4}-\d{2}-\d{2}$/.test(p.finSupport)) e.push('produit.finSupport doit être une date AAAA-MM-JJ');
  if (p.etatsMembres && !Array.isArray(p.etatsMembres)) e.push('produit.etatsMembres doit être une liste de codes pays');
  if (!cfg.fabricant?.nom) e.push('fabricant.nom est obligatoire');
  if (cfg.sources?.sbomImportees && !Array.isArray(cfg.sources.sbomImportees)) e.push('sources.sbomImportees doit être une liste');
  if (cfg.sources?.exclure && !Array.isArray(cfg.sources.exclure)) e.push('sources.exclure doit être une liste');
  return e;
}

export function lireJson(chemin, defaut) {
  if (!fs.existsSync(chemin)) return defaut;
  return JSON.parse(fs.readFileSync(chemin, 'utf8'));
}

export function ecrireJson(chemin, valeur) {
  fs.mkdirSync(path.dirname(chemin), { recursive: true });
  fs.writeFileSync(chemin, JSON.stringify(valeur, null, 2) + '\n');
}
