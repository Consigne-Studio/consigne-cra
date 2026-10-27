// Score de base CVSS v3.0 / v3.1 (spécification FIRST) et lecture prudente des autres formes.
const P = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
};
const PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };

// Arrondi supérieur à une décimale défini par CVSS 3.1 (annexe A).
function arrondiSup(x) {
  const e = Math.round(x * 100000);
  return e % 10000 === 0 ? e / 100000 : (Math.floor(e / 10000) + 1) / 10;
}

export function scoreCvss3(vecteur) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(vecteur || '');
  if (!m) return null;
  const v = Object.fromEntries(m[1].split('/').map((p) => p.split(':')));
  for (const k of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']) if (!v[k]) return null;
  const S = v.S;
  const iss = 1 - (1 - P.C[v.C]) * (1 - P.C[v.I]) * (1 - P.C[v.A]);
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const expl = 8.22 * P.AV[v.AV] * P.AC[v.AC] * PR[S][v.PR] * P.UI[v.UI];
  if ([iss, impact, expl].some(Number.isNaN)) return null;
  if (impact <= 0) return 0;
  return S === 'U' ? arrondiSup(Math.min(impact + expl, 10)) : arrondiSup(Math.min(1.08 * (impact + expl), 10));
}

export function gravite(score) {
  if (score === null || score === undefined) return 'inconnue';
  if (score === 0) return 'aucune';
  if (score < 4) return 'faible';
  if (score < 7) return 'moyenne';
  if (score < 9) return 'haute';
  return 'critique';
}

const GRAVITE_TEXTE = { LOW: 'faible', MODERATE: 'moyenne', MEDIUM: 'moyenne', HIGH: 'haute', CRITICAL: 'critique' };
export const ORDRE_GRAVITE = ['critique', 'haute', 'moyenne', 'faible', 'aucune', 'inconnue'];

// Extrait score et gravité d'un enregistrement OSV.
export function graviteOsv(vuln) {
  let meilleur = null;
  let vecteur = null;
  for (const s of vuln.severity || []) {
    if (s.type === 'CVSS_V3') {
      const sc = scoreCvss3(s.score);
      if (sc !== null && (meilleur === null || sc > meilleur)) { meilleur = sc; vecteur = s.score; }
    }
  }
  if (meilleur !== null) return { score: meilleur, gravite: gravite(meilleur), vecteur };
  const v4 = (vuln.severity || []).find((s) => s.type === 'CVSS_V4');
  const texte = vuln.database_specific?.severity || vuln.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  if (texte && GRAVITE_TEXTE[String(texte).toUpperCase()]) {
    return { score: null, gravite: GRAVITE_TEXTE[String(texte).toUpperCase()], vecteur: v4?.score || null };
  }
  return { score: null, gravite: 'inconnue', vecteur: v4?.score || null };
}
