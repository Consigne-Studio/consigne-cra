// yarn.lock v1 (classique) et Berry (v2+, format YAML simple).
import { dedoublonner } from './npm.js';

export function lireYarn(texte) {
  const res = [];
  const blocs = texte.split(/\n(?=\S)/);
  for (const bloc of blocs) {
    const lignes = bloc.split('\n');
    const tete = lignes[0];
    if (!tete || tete.startsWith('#') || tete.startsWith('__metadata')) continue;
    const ver = lignes.find((l) => /^\s+version:?\s/.test(l));
    if (!ver) continue;
    const version = ver.replace(/^\s+version:?\s+/, '').replace(/^"|"$/g, '').trim();
    const premier = tete.replace(/:$/, '').split(',')[0].trim().replace(/^"|"$/g, '');
    const at = premier.lastIndexOf('@');
    const nom = at > 0 ? premier.slice(0, at) : premier;
    const spec = at > 0 ? premier.slice(at + 1) : '';
    if (/^(workspace|link|portal|file):/.test(spec.replace(/^npm:/, '')) || spec.startsWith('workspace')) continue;
    res.push({ type: 'npm', nom, version, portee: 'run', direct: false });
  }
  return dedoublonner(res);
}
