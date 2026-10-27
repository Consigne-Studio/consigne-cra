// Recherche de vulnérabilités : OSV en ligne (api.osv.dev) ou base OSV hors ligne
// (dossier de JSON ou archives .zip publiées par OSV), croisée avec le catalogue KEV.
import fs from 'node:fs';
import path from 'node:path';
import { ECOSYSTEME_OSV } from './purl.js';
import { versionAffectee, versionsCorrectives } from './version.js';
import { graviteOsv, ORDRE_GRAVITE } from './cvss.js';
import { entreesZip } from './zip.js';

export const API_OSV = 'https://api.osv.dev/v1';
// Source officielle, puis le dépôt GitHub tenu par la CISA (même contenu) en secours.
export const URLS_KEV = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
];

const normNom = (eco, nom) => (eco === 'PyPI' ? nom.toLowerCase().replace(/[-_.]+/g, '-') : nom);
const cle = (eco, nom) => `${eco}|${normNom(eco, nom)}`;

function cibles(composants) {
  const m = new Map();
  for (const c of composants) {
    const eco = ECOSYSTEME_OSV[c.type];
    if (!eco) continue;
    const k = cle(eco, c.nom);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(c);
  }
  return m;
}

// Charge les enregistrements utiles d'une base hors ligne (seuls les paquets présents sont gardés).
export function chargerBaseHorsLigne(chemins, composants) {
  const voulus = cibles(composants);
  const enregistrements = new Map();
  let lus = 0;
  const examiner = (texte) => {
    lus++;
    let v;
    try { v = JSON.parse(texte); } catch { return; }
    if (!v?.id || !Array.isArray(v.affected)) return;
    if (v.affected.some((a) => a.package && voulus.has(cle(a.package.ecosystem?.split(':')[0], a.package.name)))) {
      enregistrements.set(v.id, v);
    }
  };
  const parcourir = (p) => {
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      for (const e of fs.readdirSync(p)) parcourir(path.join(p, e));
    } else if (p.endsWith('.zip')) {
      for (const e of entreesZip(fs.readFileSync(p))) if (e.nom.endsWith('.json')) examiner(e.lire().toString('utf8'));
    } else if (p.endsWith('.json')) {
      examiner(fs.readFileSync(p, 'utf8'));
    }
  };
  for (const c of [].concat(chemins)) {
    if (!fs.existsSync(c)) throw new Error(`Base OSV introuvable : ${c}`);
    parcourir(c);
  }
  return { enregistrements: [...enregistrements.values()], lus };
}

// Interroge api.osv.dev (requête groupée puis détail de chaque identifiant, avec cache disque).
export async function interrogerOsv(composants, { fetch = globalThis.fetch, cache, api = API_OSV } = {}) {
  const avecEco = composants.filter((c) => ECOSYSTEME_OSV[c.type]);
  const ids = new Set();
  for (let i = 0; i < avecEco.length; i += 1000) {
    const lot = avecEco.slice(i, i + 1000);
    const rep = await fetch(`${api}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: lot.map((c) => ({ package: { purl: c.purl } })) }),
    });
    if (!rep.ok) throw new Error(`OSV a répondu ${rep.status} à la requête groupée.`);
    const json = await rep.json();
    for (const r of json.results || []) for (const v of r.vulns || []) ids.add(v.id);
  }
  const enregistrements = [];
  for (const id of ids) {
    const fichierCache = cache ? path.join(cache, `${id.replace(/[^A-Za-z0-9._-]/g, '_')}.json`) : null;
    if (fichierCache && fs.existsSync(fichierCache) && Date.now() - fs.statSync(fichierCache).mtimeMs < 12 * 3600e3) {
      enregistrements.push(JSON.parse(fs.readFileSync(fichierCache, 'utf8')));
      continue;
    }
    const rep = await fetch(`${api}/vulns/${encodeURIComponent(id)}`);
    if (!rep.ok) throw new Error(`OSV a répondu ${rep.status} pour ${id}.`);
    const v = await rep.json();
    if (fichierCache) {
      fs.mkdirSync(cache, { recursive: true });
      fs.writeFileSync(fichierCache, JSON.stringify(v));
    }
    enregistrements.push(v);
  }
  return enregistrements;
}

export function chargerKev(chemin) {
  const doc = JSON.parse(fs.readFileSync(chemin, 'utf8'));
  return indexKev(doc);
}

export function indexKev(doc) {
  const m = new Map();
  for (const v of doc.vulnerabilities || []) {
    if (v.cveID) m.set(v.cveID, { dateAjout: v.dateAdded, echeance: v.dueDate, rancongiciel: v.knownRansomwareCampaignUse === 'Known', nom: v.vulnerabilityName, action: v.requiredAction });
  }
  return { index: m, version: doc.catalogVersion || null, date: doc.dateReleased || null };
}

// Croise les composants et les enregistrements OSV. Renvoie un constat par couple (vulnérabilité, composant).
export function correler(composants, enregistrements, kev = null) {
  const parCle = cibles(composants);
  const constats = [];
  const vus = new Set();
  for (const v of enregistrements) {
    if (v.withdrawn) continue;
    for (const a of v.affected || []) {
      if (!a.package) continue;
      const eco = a.package.ecosystem?.split(':')[0];
      for (const c of parCle.get(cle(eco, a.package.name)) || []) {
        if (!versionAffectee(a, c.version)) continue;
        const k = `${v.id}|${c.purl}`;
        if (vus.has(k)) continue;
        vus.add(k);
        const aliases = [...new Set([v.id, ...(v.aliases || [])])];
        const cves = aliases.filter((x) => /^CVE-\d{4}-\d+$/.test(x));
        const exploit = kev ? cves.map((x) => [x, kev.index.get(x)]).find(([, e]) => e) : null;
        const g = graviteOsv(v);
        constats.push({
          id: v.id,
          aliases,
          cve: cves[0] || null,
          purl: c.purl,
          composant: c.nom,
          version: c.version,
          direct: Boolean(c.direct),
          sources: c.sources || [],
          resume: v.summary || (v.details || '').split('\n')[0].slice(0, 200) || v.id,
          details: v.details || '',
          gravite: g.gravite,
          score: g.score,
          vecteur: g.vecteur,
          correctifs: versionsCorrectives(a),
          references: (v.references || []).slice(0, 8).map((r) => r.url),
          publie: v.published || null,
          modifie: v.modified || null,
          exploitee: Boolean(exploit),
          kev: exploit ? { cve: exploit[0], ...exploit[1] } : null,
        });
      }
    }
  }
  return trierConstats(fusionnerAlias(constats));
}

// Plusieurs bases décrivent souvent la même faille (GHSA, PYSEC, CVE…) : on garde un seul
// constat par composant, de préférence celui qui porte un score, et on réunit les alias.
const PREFERENCE = (id) => (id.startsWith('GHSA-') ? 0 : id.startsWith('CVE-') ? 2 : 1);
function fusionnerAlias(constats) {
  const parPurl = new Map();
  for (const c of constats) {
    if (!parPurl.has(c.purl)) parPurl.set(c.purl, []);
    parPurl.get(c.purl).push(c);
  }
  const res = [];
  for (const groupe of parPurl.values()) {
    const restants = [...groupe];
    while (restants.length) {
      const amas = [restants.shift()];
      const ids = new Set(amas[0].aliases);
      let change = true;
      while (change) {
        change = false;
        for (let i = restants.length - 1; i >= 0; i--) {
          if (restants[i].aliases.some((a) => ids.has(a))) {
            restants[i].aliases.forEach((a) => ids.add(a));
            amas.push(...restants.splice(i, 1));
            change = true;
          }
        }
      }
      amas.sort((a, b) => (Number(b.score !== null) - Number(a.score !== null)) || PREFERENCE(a.id) - PREFERENCE(b.id) || a.id.localeCompare(b.id));
      const g = { ...amas[0] };
      g.aliases = [g.id, ...[...ids].filter((x) => x !== g.id).sort()];
      g.cve = g.cve || g.aliases.find((x) => /^CVE-\d{4}-\d+$/.test(x)) || null;
      g.correctifs = [...new Set(amas.flatMap((x) => x.correctifs))];
      g.exploitee = amas.some((x) => x.exploitee);
      g.kev = amas.find((x) => x.kev)?.kev || null;
      res.push(g);
    }
  }
  return res;
}

export function trierConstats(liste) {
  return liste.sort((a, b) => (Number(b.exploitee) - Number(a.exploitee))
    || ORDRE_GRAVITE.indexOf(a.gravite) - ORDRE_GRAVITE.indexOf(b.gravite)
    || (b.score ?? -1) - (a.score ?? -1)
    || a.id.localeCompare(b.id) || a.purl.localeCompare(b.purl));
}
