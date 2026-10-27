// pnpm-lock.yaml (lockfileVersion 5 à 9). Lecture ligne à ligne de la section `packages:`,
// suffisante pour ce format très régulier ; pas de dépendance YAML.
import { dedoublonner } from './npm.js';

export function lirePnpm(texte) {
  const res = [];
  const lignes = texte.split(/\r?\n/);
  let dansPackages = false;
  let courant = null;
  for (const l of lignes) {
    if (/^packages:\s*$/.test(l)) { dansPackages = true; continue; }
    if (/^\S/.test(l)) { dansPackages = false; courant = null; continue; }
    if (!dansPackages) continue;
    const cle = /^ {2}['"]?(\/?[^'"\s][^'"]*?)['"]?:\s*$/.exec(l);
    if (cle) {
      const brut = cle[1].replace(/^\//, '').replace(/\(.*$/, '');
      // v9 : nom@version ; v6 : /nom@version ; v5 : /nom/version
      let nom; let version;
      const at = brut.lastIndexOf('@');
      if (at > 0) { nom = brut.slice(0, at); version = brut.slice(at + 1); } else {
        const i = brut.lastIndexOf('/');
        nom = brut.slice(0, i); version = brut.slice(i + 1);
      }
      courant = { type: 'npm', nom, version: version.replace(/_.*$/, ''), portee: 'run', direct: false };
      res.push(courant);
    } else if (courant && /^ {4}dev: true/.test(l)) {
      courant.portee = 'dev';
    }
  }
  return dedoublonner(res.filter((c) => c.nom && /^\d/.test(c.version)));
}
