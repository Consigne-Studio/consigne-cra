// Commandes communes aux deux éditions : inventaire (SBOM), vulnérabilités (OSV, KEV),
// triage et VEX. L'édition complète ajoute les signalements, les exigences et les rendus.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { lireJson, ecrireJson } from './config.js';
import { collecterComposants, construireCycloneDx, verifierSbom } from './sbom.js';
import { chargerBaseHorsLigne, interrogerOsv, correler, chargerKev, indexKev, URLS_KEV, API_OSV } from './osv.js';
import { registreVide as triageVide, enregistrerDecision, enrichir, STATUTS, JUSTIFICATIONS, REPONSES, vexCycloneDx, vexOpenVex, vexCsaf } from './triage.js';

export const fichiers = (cfg) => ({
  sbom: path.join(cfg.dossierSortie, 'sbom.cdx.json'),
  scan: path.join(cfg.dossierDonnees, 'scan.json'),
  triage: path.join(cfg.dossierDonnees, 'triage.json'),
  incidents: path.join(cfg.dossierDonnees, 'incidents.json'),
  exigences: path.join(cfg.dossierDonnees, 'exigences.json'),
  sections: path.join(cfg.dossierDonnees, 'dossier'),
  cache: path.join(cfg.dossierDonnees, 'cache'),
});

export function analyserArgs(argv) {
  const pos = [];
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { pos.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const [k, v0] = a.slice(2).split(/=(.*)/s);
      let v = v0;
      if (v === undefined) {
        const suivant = argv[i + 1];
        if (suivant !== undefined && !suivant.startsWith('--')) { v = suivant; i++; } else v = true;
      }
      if (opt[k] === undefined) opt[k] = v;
      else opt[k] = [].concat(opt[k], v);
    } else if (a === '-h') opt.aide = true;
    else pos.push(a);
  }
  return { pos, opt };
}

export const liste = (v) => (v === undefined ? [] : [].concat(v));
export const texte = (v) => (Array.isArray(v) ? v[v.length - 1] : v === true ? '' : v);
export const auteurPar = (opt) => texte(opt.auteur) || process.env.CRA_AUTEUR || os.userInfo().username;

export class Sortie {
  constructor(ecrire = (s) => process.stdout.write(s + '\n'), erreur = (s) => process.stderr.write(s + '\n')) {
    this.ecrire = ecrire;
    this.erreur = erreur;
  }
}

export function sbom(cfg, out, maintenant) {
  const { verrous, composants } = collecterComposants(cfg);
  const bom = construireCycloneDx(cfg, composants, maintenant);
  const erreurs = verifierSbom(bom);
  if (erreurs.length) throw new Error(`SBOM invalide :\n- ${erreurs.join('\n- ')}`);
  const f = fichiers(cfg);
  ecrireJson(f.sbom, bom);
  out.ecrire(`SBOM : ${composants.length} composants depuis ${verrous.length} verrou(s)${cfg.sources?.sbomImportees?.length ? ` et ${cfg.sources.sbomImportees.length} SBOM importée(s)` : ''} → ${path.relative(process.cwd(), f.sbom) || f.sbom}`);
  if (!verrous.length && !cfg.sources?.sbomImportees?.length) out.erreur('Attention : aucun fichier de verrouillage trouvé sous ' + cfg.racine);
  return bom;
}

export async function scan(cfg, opt, out, deps) {
  const f = fichiers(cfg);
  const bom = lireJson(f.sbom, null) || sbom(cfg, out, deps.maintenant);
  const composants = bom.components.map((c) => {
    const [type] = c.purl.replace(/^pkg:/, '').split('/');
    return { type, nom: nomDepuisPurl(c), version: c.version, purl: c.purl, direct: (c.properties || []).some((p) => p.name === 'cra:dependance-directe'), sources: ((c.properties || []).find((p) => p.name === 'cra:source')?.value || '').split(', ').filter(Boolean) };
  });
  const horsLigne = liste(opt['hors-ligne']).map((p) => path.resolve(deps.cwd, p));
  let enregistrements;
  let base;
  if (horsLigne.length) {
    const r = chargerBaseHorsLigne(horsLigne, composants);
    enregistrements = r.enregistrements;
    const dates = horsLigne.map((p) => fs.statSync(p).mtime.toISOString().slice(0, 10));
    base = `OSV hors ligne (${r.lus} enregistrements lus, fichiers du ${[...new Set(dates)].join(', ')})`;
  } else {
    enregistrements = await interrogerOsv(composants, { fetch: deps.fetch, cache: path.join(f.cache, 'osv'), api: process.env.CRA_OSV_API || API_OSV });
    base = `OSV en ligne (${process.env.CRA_OSV_API || 'api.osv.dev'})`;
  }
  let kev = null;
  let kevSource = null;
  if (!opt['sans-kev']) {
    if (opt.kev) {
      kev = chargerKev(path.resolve(deps.cwd, texte(opt.kev)));
      kevSource = path.basename(texte(opt.kev));
    } else if (!horsLigne.length) {
      kev = await telechargerKev(f.cache, deps.fetch, out);
      kevSource = kev ? 'cisa.gov' : null;
    } else {
      out.erreur('Attention : mode hors ligne sans --kev, l\'exploitation active (art. 14) ne sera pas détectée.');
    }
  }
  const constats = correler(composants, enregistrements, kev);
  const resultat = { date: deps.maintenant.toISOString(), base, kev: kev ? { version: kev.version, date: kev.date, source: kevSource } : null, composants: composants.length, constats };
  ecrireJson(f.scan, resultat);
  const triage = lireJson(f.triage, triageVide());
  const enr = enrichir(constats, triage);
  const ids = new Set(constats.map((c) => c.id)).size;
  out.ecrire(`Analyse : ${composants.length} composants, ${ids} vulnérabilité(s), ${constats.length} constat(s), dont ${constats.filter((c) => c.exploitee).length} exploité(s) activement ; ${enr.filter((c) => c.statut === 'non_trie').length} sans décision.`);
  return resultat;
}

function nomDepuisPurl(c) {
  const m = /^pkg:[a-z]+\/(.+?)@/.exec(c.purl);
  if (!m) return c.name;
  const segs = m[1].split('/').map(decodeURIComponent);
  if (c.purl.startsWith('pkg:maven/')) return segs.join(':');
  return segs.join('/');
}

async function telechargerKev(cache, fetchFn, out) {
  const p = path.join(cache, 'kev.json');
  if (fs.existsSync(p) && Date.now() - fs.statSync(p).mtimeMs < 24 * 3600e3) return chargerKev(p);
  let derniere = null;
  for (const url of URLS_KEV) {
    try {
      const rep = await fetchFn(url);
      if (!rep.ok) throw new Error(`HTTP ${rep.status}`);
      const doc = await rep.json();
      if (!Array.isArray(doc.vulnerabilities)) throw new Error('format inattendu');
      fs.mkdirSync(cache, { recursive: true });
      fs.writeFileSync(p, JSON.stringify(doc));
      return indexKev(doc);
    } catch (e) {
      derniere = e;
    }
  }
  if (fs.existsSync(p)) { out.erreur(`KEV indisponible (${derniere.message}) : copie locale du ${fs.statSync(p).mtime.toISOString().slice(0, 10)} utilisée.`); return chargerKev(p); }
  out.erreur(`Attention : catalogue KEV indisponible (${derniere.message}). Utilisez --kev <fichier> ; l'exploitation active ne sera pas détectée.`);
  return null;
}

export function triage(cfg, pos, opt, out, maintenant) {
  const f = fichiers(cfg);
  const scanRes = lireJson(f.scan, null);
  const registre = lireJson(f.triage, triageVide());
  const [id] = pos;
  if (!id) {
    if (!scanRes) throw new Error('Aucune analyse : lancez « cra scan ».');
    const a = enrichir(scanRes.constats, registre).filter((c) => c.statut === 'non_trie');
    if (!a.length) { out.ecrire('Tous les constats ont une décision.'); return; }
    for (const c of a) out.ecrire(`${c.exploitee ? 'KEV ' : '    '}${c.gravite.padEnd(9)} ${c.id.padEnd(22)} ${c.composant}@${c.version}  ${c.resume.slice(0, 70)}`);
    out.ecrire(`\n${a.length} constat(s) sans décision. Statuts : ${Object.keys(STATUTS).join(', ')}. Justifications : ${Object.keys(JUSTIFICATIONS).join(', ')}. Réponses : ${REPONSES.join(', ')}.`);
    return;
  }
  let purls = [null];
  const comp = texte(opt.composant);
  if (comp) {
    if (comp.startsWith('pkg:')) purls = [comp];
    else {
      const trouves = [...new Set((scanRes?.constats || []).filter((c) => (c.id === id || c.aliases.includes(id)) && c.composant === comp).map((c) => c.purl))];
      if (!trouves.length) throw new Error(`Aucun constat ${id} pour le composant « ${comp} » dans la dernière analyse.`);
      purls = trouves;
    }
  } else if (scanRes && !scanRes.constats.some((c) => c.id === id || c.aliases.includes(id))) {
    out.erreur(`Attention : ${id} n'apparaît pas dans la dernière analyse ; décision enregistrée quand même.`);
  }
  for (const purl of purls) {
    enregistrerDecision(registre, { id, purl, statut: texte(opt.statut), justification: texte(opt.justification), detail: texte(opt.detail), reponse: texte(opt.reponse), auteur: auteurPar(opt), date: maintenant });
  }
  ecrireJson(f.triage, registre);
  out.ecrire(`Décision enregistrée : ${id}${purls[0] ? ' / ' + purls.join(', ') : ''} → ${texte(opt.statut)}`);
}

export function vex(cfg, out, maintenant) {
  const f = fichiers(cfg);
  const scanRes = lireJson(f.scan, null);
  if (!scanRes) throw new Error('Aucune analyse : lancez « cra scan ».');
  const constats = enrichir(scanRes.constats, lireJson(f.triage, triageVide()));
  const d = cfg.dossierSortie;
  ecrireJson(path.join(d, 'vex.cdx.json'), vexCycloneDx(cfg, constats, maintenant));
  ecrireJson(path.join(d, 'vex.openvex.json'), vexOpenVex(cfg, constats, maintenant));
  ecrireJson(path.join(d, 'vex.csaf.json'), vexCsaf(cfg, constats, maintenant));
  out.ecrire(`VEX : ${constats.length} déclaration(s) → vex.cdx.json, vex.openvex.json, vex.csaf.json`);
}
