// Registre de triage (analyse d'exploitabilité) et exports VEX : CycloneDX 1.6, OpenVEX 0.2, CSAF 2.0.
import crypto from 'node:crypto';
import { VERSION_OUTIL } from './version-outil.js';

export const STATUTS = {
  en_analyse: { cdx: 'in_triage', openvex: 'under_investigation', csaf: 'under_investigation', libelle: 'En analyse' },
  affecte: { cdx: 'exploitable', openvex: 'affected', csaf: 'known_affected', libelle: 'Affecté' },
  non_affecte: { cdx: 'not_affected', openvex: 'not_affected', csaf: 'known_not_affected', libelle: 'Non affecté' },
  faux_positif: { cdx: 'false_positive', openvex: 'not_affected', csaf: 'known_not_affected', libelle: 'Faux positif' },
  corrige: { cdx: 'resolved', openvex: 'fixed', csaf: 'fixed', libelle: 'Corrigé' },
};

// Justifications CycloneDX et leur équivalent OpenVEX / CSAF.
export const JUSTIFICATIONS = {
  code_not_present: { openvex: 'vulnerable_code_not_present', csaf: 'vulnerable_code_not_present', libelle: 'Code vulnérable absent' },
  code_not_reachable: { openvex: 'vulnerable_code_not_in_execute_path', csaf: 'vulnerable_code_not_in_execute_path', libelle: 'Code vulnérable non atteignable' },
  requires_configuration: { openvex: 'vulnerable_code_cannot_be_controlled_by_adversary', csaf: 'vulnerable_code_cannot_be_controlled_by_adversary', libelle: 'Exige une configuration absente' },
  requires_dependency: { openvex: 'vulnerable_code_cannot_be_controlled_by_adversary', csaf: 'vulnerable_code_cannot_be_controlled_by_adversary', libelle: 'Exige une dépendance absente' },
  requires_environment: { openvex: 'vulnerable_code_cannot_be_controlled_by_adversary', csaf: 'vulnerable_code_cannot_be_controlled_by_adversary', libelle: 'Exige un environnement absent' },
  protected_by_compiler: { openvex: 'inline_mitigations_already_exist', csaf: 'inline_mitigations_already_exist', libelle: 'Protégé par le compilateur' },
  protected_at_runtime: { openvex: 'inline_mitigations_already_exist', csaf: 'inline_mitigations_already_exist', libelle: 'Protégé à l\'exécution' },
  protected_at_perimeter: { openvex: 'inline_mitigations_already_exist', csaf: 'inline_mitigations_already_exist', libelle: 'Protégé en périphérie' },
  protected_by_mitigating_control: { openvex: 'inline_mitigations_already_exist', csaf: 'inline_mitigations_already_exist', libelle: 'Protégé par une mesure d\'atténuation' },
};

export const REPONSES = ['update', 'workaround_available', 'will_not_fix', 'rollback', 'can_not_fix'];

export function registreVide() { return { version: 1, decisions: {} }; }

export function cleDecision(id, purl) { return purl ? `${id}|${purl}` : id; }

// Une décision peut viser un couple (vulnérabilité, composant) ou la vulnérabilité entière.
export function decisionPour(registre, constat) {
  const d = registre.decisions || {};
  return d[cleDecision(constat.id, constat.purl)] || d[constat.id] || constat.aliases?.map((a) => d[cleDecision(a, constat.purl)] || d[a]).find(Boolean) || null;
}

export function enregistrerDecision(registre, { id, purl, statut, justification, detail, reponse, auteur, date = new Date() }) {
  const erreurs = [];
  if (!STATUTS[statut]) erreurs.push(`statut inconnu « ${statut} » (valeurs : ${Object.keys(STATUTS).join(', ')})`);
  if ((statut === 'non_affecte') && !justification && !detail) erreurs.push('un statut non_affecte exige --justification ou --detail (preuve attendue par un auditeur)');
  if (justification && !JUSTIFICATIONS[justification]) erreurs.push(`justification inconnue « ${justification} » (valeurs : ${Object.keys(JUSTIFICATIONS).join(', ')})`);
  if (reponse && !REPONSES.includes(reponse)) erreurs.push(`réponse inconnue « ${reponse} » (valeurs : ${REPONSES.join(', ')})`);
  if (statut === 'affecte' && !detail && !reponse) erreurs.push('un statut affecte exige --reponse ou --detail (action prévue)');
  if (erreurs.length) throw new Error(erreurs.join('\n'));
  const k = cleDecision(id, purl);
  const avant = registre.decisions[k];
  registre.decisions[k] = {
    statut, justification: justification || null, detail: detail || '', reponse: reponse || null,
    auteur: auteur || null, date: date.toISOString(),
    historique: avant ? [...(avant.historique || []), { statut: avant.statut, date: avant.date, auteur: avant.auteur }] : [],
  };
  return registre.decisions[k];
}

export function enrichir(constats, registre) {
  return constats.map((c) => {
    const d = decisionPour(registre, c);
    return { ...c, decision: d, statut: d?.statut || 'non_trie' };
  });
}

// Une vulnérabilité est « ouverte » tant qu'elle n'est pas écartée ou corrigée.
export const estOuverte = (c) => !['non_affecte', 'faux_positif', 'corrige'].includes(c.statut);

const refProduit = (cfg) => `produit:${cfg.produit.nom}@${cfg.produit.version}`;

export function vexCycloneDx(cfg, constats, horodatage = new Date()) {
  const parVuln = new Map();
  for (const c of constats) {
    if (!parVuln.has(c.id)) parVuln.set(c.id, []);
    parVuln.get(c.id).push(c);
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: horodatage.toISOString(),
      tools: { components: [{ type: 'application', name: 'consigne-cra', version: VERSION_OUTIL }] },
      component: { type: 'application', 'bom-ref': refProduit(cfg), name: cfg.produit.nom, version: cfg.produit.version },
    },
    vulnerabilities: [...parVuln.entries()].map(([id, liste]) => {
      const c = liste[0];
      const d = c.decision;
      return {
        id,
        source: { name: id.startsWith('GHSA') ? 'GitHub Advisory' : 'OSV', url: `https://osv.dev/vulnerability/${id}` },
        references: c.aliases.filter((a) => a !== id).map((a) => ({ id: a, source: { name: a.startsWith('CVE') ? 'NVD' : 'OSV' } })),
        ratings: c.score !== null ? [{ score: c.score, severity: { critique: 'critical', haute: 'high', moyenne: 'medium', faible: 'low' }[c.gravite] || 'unknown', method: 'CVSSv31', vector: c.vecteur }] : undefined,
        description: c.resume,
        published: c.publie || undefined,
        updated: c.modifie || undefined,
        analysis: {
          state: STATUTS[c.statut]?.cdx || 'in_triage',
          justification: d?.justification || undefined,
          response: d?.reponse ? [d.reponse] : undefined,
          detail: d?.detail || (c.statut === 'non_trie' ? 'Pas encore analysée.' : undefined),
          lastUpdated: d?.date || undefined,
        },
        affects: liste.map((x) => ({ ref: x.purl })),
        properties: c.exploitee ? [{ name: 'cra:exploitee-activement', value: `CISA KEV ${c.kev.dateAjout}` }] : undefined,
      };
    }),
  };
}

export function vexOpenVex(cfg, constats, horodatage = new Date()) {
  const produit = `pkg:generic/${encodeURIComponent(cfg.produit.nom)}@${encodeURIComponent(cfg.produit.version)}`;
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${crypto.randomUUID()}`,
    author: cfg.fabricant.nom,
    timestamp: horodatage.toISOString(),
    version: 1,
    tooling: `consigne-cra/${VERSION_OUTIL}`,
    statements: constats.map((c) => {
      const d = c.decision;
      const statut = STATUTS[c.statut]?.openvex || 'under_investigation';
      const s = {
        vulnerability: { name: c.cve || c.id, aliases: c.aliases.filter((a) => a !== (c.cve || c.id)) },
        products: [{ '@id': produit, subcomponents: [{ '@id': c.purl }] }],
        status: statut,
        timestamp: d?.date || horodatage.toISOString(),
      };
      if (statut === 'not_affected') {
        if (d?.justification) s.justification = JUSTIFICATIONS[d.justification].openvex;
        s.impact_statement = d?.detail || (c.statut === 'faux_positif' ? 'Faux positif de la détection automatique.' : undefined);
        if (!s.justification && !s.impact_statement) s.impact_statement = 'Non affecté.';
      }
      if (statut === 'affected') s.action_statement = d?.detail || `Réponse prévue : ${d?.reponse}`;
      if (statut === 'under_investigation' && d?.detail) s.status_notes = d.detail;
      return s;
    }),
  };
}

export function vexCsaf(cfg, constats, horodatage = new Date()) {
  const idProduit = 'CSAFPID-0001';
  const composants = [...new Map(constats.map((c) => [c.purl, c])).values()];
  const idComposant = new Map(composants.map((c, i) => [c.purl, `CSAFPID-${String(i + 2).padStart(4, '0')}`]));
  const idRelation = (purl) => `${idProduit}:${idComposant.get(purl)}`;
  const parVuln = new Map();
  for (const c of constats) {
    if (!parVuln.has(c.id)) parVuln.set(c.id, []);
    parVuln.get(c.id).push(c);
  }
  const date = horodatage.toISOString();
  const trackingId = `${cfg.produit.nom}-${cfg.produit.version}-vex`.toLowerCase().replace(/[^a-z0-9.-]+/g, '-');
  return {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      lang: 'fr',
      publisher: { category: 'vendor', name: cfg.fabricant.nom, namespace: cfg.fabricant.site || 'https://exemple.invalid' },
      title: `VEX ${cfg.produit.nom} ${cfg.produit.version}`,
      tracking: {
        id: trackingId,
        status: 'interim',
        version: '1',
        initial_release_date: date,
        current_release_date: date,
        revision_history: [{ date, number: '1', summary: 'Version générée par consigne-cra.' }],
        generator: { engine: { name: 'consigne-cra', version: VERSION_OUTIL } },
      },
    },
    product_tree: {
      branches: [{
        category: 'vendor', name: cfg.fabricant.nom,
        branches: [{ category: 'product_name', name: cfg.produit.nom, branches: [{ category: 'product_version', name: cfg.produit.version, product: { product_id: idProduit, name: `${cfg.produit.nom} ${cfg.produit.version}` } }] }],
      }],
      full_product_names: composants.map((c) => ({ product_id: idComposant.get(c.purl), name: `${c.composant} ${c.version}`, product_identification_helper: { purl: c.purl } })),
      relationships: composants.map((c) => ({
        category: 'default_component_of',
        product_reference: idComposant.get(c.purl),
        relates_to_product_reference: idProduit,
        full_product_name: { product_id: idRelation(c.purl), name: `${c.composant} ${c.version} dans ${cfg.produit.nom} ${cfg.produit.version}` },
      })),
    },
    vulnerabilities: [...parVuln.entries()].map(([id, liste]) => {
      const etat = {};
      const flags = [];
      const remediations = [];
      const threats = [];
      for (const c of liste) {
        const csaf = STATUTS[c.statut]?.csaf || 'under_investigation';
        (etat[csaf] ||= []).push(idRelation(c.purl));
        const d = c.decision;
        if (csaf === 'known_not_affected') {
          if (d?.justification) flags.push({ label: JUSTIFICATIONS[d.justification].csaf, product_ids: [idRelation(c.purl)] });
          else threats.push({ category: 'impact', details: d?.detail || 'Faux positif.', product_ids: [idRelation(c.purl)] });
        }
        if (csaf === 'known_affected') {
          remediations.push({ category: d?.reponse === 'workaround_available' ? 'workaround' : d?.reponse === 'will_not_fix' || d?.reponse === 'can_not_fix' ? 'no_fix_planned' : 'vendor_fix', details: d?.detail || `Mettre à jour vers ${c.correctifs.join(' ou ') || 'une version corrigée'}.`, product_ids: [idRelation(c.purl)] });
        }
      }
      const c = liste[0];
      const v = { notes: [{ category: 'summary', text: c.resume }], product_status: etat, ids: [{ system_name: 'OSV', text: id }] };
      if (c.cve) v.cve = c.cve;
      if (flags.length) v.flags = flags;
      if (remediations.length) v.remediations = remediations;
      if (threats.length) v.threats = threats;
      return v;
    }),
  };
}
