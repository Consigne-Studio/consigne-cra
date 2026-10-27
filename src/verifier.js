// Garde-fou d'intégration continue : liste les points bloquants et fixe le code de sortie.
import { ORDRE_GRAVITE } from './cvss.js';
import { verifierSbom } from './sbom.js';

const dateCourte = (iso) => `${iso.slice(0, 16).replace('T', ' ')} UTC`;

export function verifier(etat, { seuil = 'haute', maxAgeHeures = 24 * 7 } = {}) {
  const bloquants = [];
  const avertissements = [];
  const { bom, scan, constats, incidents, maintenant } = etat;
  const rang = ORDRE_GRAVITE.indexOf(seuil);
  if (rang < 0) throw new Error(`seuil inconnu « ${seuil} » (valeurs : critique, haute, moyenne, faible)`);

  if (!bom) bloquants.push({ code: 'sbom-absente', message: 'Aucune SBOM : lancez « cra sbom ».' });
  else {
    for (const e of verifierSbom(bom)) bloquants.push({ code: 'sbom-invalide', message: e });
    if (!(bom.components || []).length) bloquants.push({ code: 'sbom-vide', message: 'La SBOM ne contient aucun composant : vérifiez sources.racine, les fichiers de verrouillage et sources.sbomImportees.' });
  }

  if (!scan) bloquants.push({ code: 'scan-absent', message: 'Aucune analyse de vulnérabilités : lancez « cra scan ».' });
  else {
    const age = (maintenant - new Date(scan.date)) / 3600e3;
    if (age > maxAgeHeures) avertissements.push({ code: 'scan-ancien', message: `Dernière analyse il y a ${age >= 48 ? `${Math.round(age / 24)} jours` : `${Math.round(age)} h`} (plus de ${maxAgeHeures} h).` });
    if (!scan.kev) avertissements.push({ code: 'kev-absent', message: 'Catalogue des vulnérabilités exploitées (KEV) non consulté : l\'exploitation active n\'est pas détectée.' });
  }

  for (const c of constats) {
    const ouverte = c.statut === 'non_trie' || c.statut === 'en_analyse' || c.statut === 'affecte';
    if (!ouverte) continue;
    const ref = `${c.id} dans ${c.composant} ${c.version}`;
    if (c.exploitee) {
      const suite = c.statut === 'affecte'
        ? 'produit affecté, correctif à livrer (statut « corrige » une fois diffusé) et signalement art. 14 à suivre'
        : 'triage immédiat, et signalement art. 14 si le produit est affecté';
      bloquants.push({ code: 'exploitee', message: `${ref} est activement exploitée (KEV ${c.kev.dateAjout}) : ${suite}.`, id: c.id, purl: c.purl });
    } else if (c.statut === 'non_trie' && ORDRE_GRAVITE.indexOf(c.gravite) <= rang && c.gravite !== 'inconnue') {
      bloquants.push({ code: 'non-triee', message: `${ref} (${c.gravite}) n'a pas de décision.`, id: c.id, purl: c.purl });
    } else if (c.statut === 'non_trie') {
      avertissements.push({ code: 'non-triee', message: `${ref} (${c.gravite}) n'a pas de décision.`, id: c.id, purl: c.purl });
    }
  }

  for (const i of incidents) {
    for (const e of i.echeances) {
      if (e.etat === 'en_retard') bloquants.push({ code: 'echeance-depassee', message: `${i.id} : échéance « ${e.libelle} » dépassée depuis le ${dateCourte(e.limite)}.` });
      else if (e.etat === 'imminent') avertissements.push({ code: 'echeance-proche', message: `${i.id} : échéance « ${e.libelle} » avant le ${dateCourte(e.limite)} (reste ${e.resteHeures} h).` });
    }
  }

  const fin = etat.cfg.produit.finSupport ? new Date(etat.cfg.produit.finSupport) : null;
  if (fin && fin < maintenant) avertissements.push({ code: 'fin-support', message: `Période d'assistance terminée depuis le ${etat.cfg.produit.finSupport}.` });

  return { ok: bloquants.length === 0, bloquants, avertissements };
}

export function formater(resultat, format = 'texte') {
  if (format === 'json') return JSON.stringify(resultat, null, 2);
  if (format === 'github') {
    return [
      ...resultat.bloquants.map((b) => `::error title=CRA ${b.code}::${b.message}`),
      ...resultat.avertissements.map((a) => `::warning title=CRA ${a.code}::${a.message}`),
    ].join('\n');
  }
  const l = [];
  for (const b of resultat.bloquants) l.push(`BLOQUANT  ${b.message}`);
  const nonTriees = resultat.avertissements.filter((a) => a.code === 'non-triee');
  for (const a of resultat.avertissements) if (a.code !== 'non-triee' || nonTriees.length <= 5) l.push(`ATTENTION ${a.message}`);
  if (nonTriees.length > 5) l.push(`ATTENTION ${nonTriees.length} autres constats sous le seuil sont sans décision (« cra triage » pour la liste).`);
  l.push(resultat.ok ? 'Garde-fou CRA : aucun point bloquant.' : `Garde-fou CRA : ${resultat.bloquants.length} point(s) bloquant(s).`);
  return l.join('\n');
}
