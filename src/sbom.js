// SBOM CycloneDX 1.6 : génération depuis les verrous, import CycloneDX et SPDX (JSON).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { purl, lirePurl } from './purl.js';
import { trouverVerrous, lireVerrou } from './lockfiles/index.js';
import { VERSION_OUTIL } from './version-outil.js';

export function collecterComposants(cfg) {
  const verrous = trouverVerrous(cfg.racine, 4, cfg.sources?.exclure || []);
  const composants = [];
  for (const v of verrous) composants.push(...lireVerrou(v, cfg.racine));
  for (const f of cfg.sources?.sbomImportees || []) {
    composants.push(...importerSbom(path.resolve(cfg.base, f)));
  }
  const filtres = cfg.sources?.inclureDev ? composants : composants.filter((c) => c.portee !== 'dev');
  return { verrous: verrous.map((v) => path.relative(cfg.racine, v.chemin).split(path.sep).join('/')), composants: fusionner(filtres) };
}

function fusionner(liste) {
  const m = new Map();
  for (const c of liste) {
    const p = c.purl || purl(c.type, c.nom, c.version);
    const avant = m.get(p);
    if (avant) {
      avant.sources = [...new Set([...avant.sources, c.source])];
      avant.direct = avant.direct || c.direct;
    } else {
      m.set(p, { ...c, purl: p, sources: [c.source] });
    }
  }
  return [...m.values()].sort((a, b) => a.purl.localeCompare(b.purl));
}

export function importerSbom(chemin) {
  const doc = JSON.parse(fs.readFileSync(chemin, 'utf8'));
  const source = path.basename(chemin);
  const res = [];
  if (doc.bomFormat === 'CycloneDX') {
    const visiter = (liste) => {
      for (const c of liste || []) {
        if (c.purl) {
          const p = lirePurl(c.purl);
          res.push({ type: p?.type || 'generic', nom: p?.nom || c.name, version: c.version || p?.version, purl: c.purl.replace(/\?.*$/, ''), portee: c.scope === 'optional' ? 'dev' : 'run', direct: false, source, licences: licencesCdx(c) });
        } else if (c.name && c.version) {
          res.push({ type: 'generic', nom: c.name, version: c.version, purl: `pkg:generic/${encodeURIComponent(c.name)}@${encodeURIComponent(c.version)}`, portee: 'run', direct: false, source });
        }
        visiter(c.components);
      }
    };
    visiter(doc.components);
  } else if (doc.spdxVersion) {
    for (const p of doc.packages || []) {
      const ref = (p.externalRefs || []).find((r) => r.referenceType === 'purl');
      if (!ref) continue;
      const lu = lirePurl(ref.referenceLocator);
      res.push({ type: lu?.type || 'generic', nom: lu?.nom || p.name, version: p.versionInfo || lu?.version, purl: ref.referenceLocator.replace(/\?.*$/, ''), portee: 'run', direct: false, source, licences: p.licenseConcluded && p.licenseConcluded !== 'NOASSERTION' ? [p.licenseConcluded] : [] });
    }
  } else {
    throw new Error(`${source} : format SBOM non reconnu (CycloneDX JSON ou SPDX JSON attendu).`);
  }
  return res;
}

function licencesCdx(c) {
  return (c.licenses || []).map((l) => l.license?.id || l.license?.name || l.expression).filter(Boolean);
}

// Identifiant stable : même produit + mêmes composants => même numéro de série.
function numeroSerie(cfg, composants) {
  const h = crypto.createHash('sha256').update(`${cfg.produit.nom}|${cfg.produit.version}|${composants.map((c) => c.purl).join(',')}`).digest('hex');
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function construireCycloneDx(cfg, composants, horodatage = new Date()) {
  const refProduit = `produit:${cfg.produit.nom}@${cfg.produit.version}`;
  const directs = composants.filter((c) => c.direct).map((c) => c.purl);
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: numeroSerie(cfg, composants),
    version: 1,
    metadata: {
      timestamp: horodatage.toISOString(),
      lifecycles: [{ phase: 'build' }],
      tools: { components: [{ type: 'application', name: 'consigne-cra', version: VERSION_OUTIL }] },
      manufacturer: { name: cfg.fabricant.nom, url: cfg.fabricant.site ? [cfg.fabricant.site] : undefined, contact: cfg.fabricant.email ? [{ email: cfg.fabricant.email }] : undefined },
      component: { type: cfg.produit.type === 'materiel' ? 'device' : 'application', 'bom-ref': refProduit, name: cfg.produit.nom, version: cfg.produit.version, description: cfg.produit.description },
      properties: [
        { name: 'cra:categorie', value: cfg.produit.categorie || 'defaut' },
        { name: 'cra:fin-support', value: cfg.produit.finSupport || '' },
      ],
    },
    components: composants.map((c) => ({
      type: 'library',
      'bom-ref': c.purl,
      name: c.nom,
      version: c.version,
      purl: c.purl,
      scope: c.portee === 'dev' ? 'optional' : 'required',
      hashes: hashCdx(c.integrite),
      licenses: c.licences?.length ? c.licences.map((id) => ({ license: /^[A-Za-z0-9.+-]+$/.test(id) ? { id } : { name: id } })) : undefined,
      properties: [{ name: 'cra:source', value: c.sources.join(', ') }, ...(c.direct ? [{ name: 'cra:dependance-directe', value: 'oui' }] : [])],
    })),
    dependencies: [{ ref: refProduit, dependsOn: directs }],
  };
}

function hashCdx(integrite) {
  if (!integrite) return undefined;
  const m = /^(sha512|sha256|sha1)-(.+)$/.exec(integrite);
  if (!m) return undefined;
  const alg = { sha512: 'SHA-512', sha256: 'SHA-256', sha1: 'SHA-1' }[m[1]];
  const contenu = /^[0-9a-f]+$/i.test(m[2]) ? m[2].toLowerCase() : Buffer.from(m[2], 'base64').toString('hex');
  return [{ alg, content: contenu }];
}

// Contrôle minimal de structure (champs exigés par CycloneDX 1.6 et utiles au CRA).
export function verifierSbom(bom) {
  const e = [];
  if (bom.bomFormat !== 'CycloneDX') e.push('bomFormat doit valoir CycloneDX');
  if (bom.specVersion !== '1.6') e.push('specVersion 1.6 attendue');
  if (!/^urn:uuid:[0-9a-f-]{36}$/.test(bom.serialNumber || '')) e.push('serialNumber doit être un urn:uuid');
  if (!bom.metadata?.component?.name) e.push('metadata.component.name manquant');
  if (!bom.metadata?.manufacturer?.name) e.push('metadata.manufacturer.name manquant (fabricant)');
  const refs = new Set();
  for (const c of bom.components || []) {
    if (!c.name || !c.version) e.push(`composant sans nom ou version : ${JSON.stringify(c).slice(0, 80)}`);
    if (!c.purl) e.push(`composant sans purl : ${c.name}`);
    if (refs.has(c['bom-ref'])) e.push(`bom-ref en double : ${c['bom-ref']}`);
    refs.add(c['bom-ref']);
  }
  for (const d of bom.dependencies || []) for (const r of d.dependsOn || []) if (!refs.has(r)) e.push(`dépendance vers un bom-ref absent : ${r}`);
  return e;
}
