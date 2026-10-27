// composer.lock (PHP).
import { dedoublonner } from './npm.js';

export function lireComposer(texte) {
  const lock = JSON.parse(texte);
  const res = [];
  for (const [cle, portee] of [['packages', 'run'], ['packages-dev', 'dev']]) {
    for (const p of lock[cle] || []) {
      if (p.name && p.version) res.push({ type: 'composer', nom: p.name, version: p.version.replace(/^v/, ''), portee, direct: false });
    }
  }
  return dedoublonner(res);
}
