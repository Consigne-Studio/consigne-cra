// requirements.txt (versions épinglées avec ==) et poetry.lock.
import { dedoublonner } from './npm.js';

export function lireRequirements(texte) {
  const res = [];
  for (const brut of texte.split(/\r?\n/)) {
    const l = brut.replace(/\s+#.*$/, '').trim();
    if (!l || l.startsWith('#') || l.startsWith('-')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/.exec(l);
    if (m) res.push({ type: 'pypi', nom: m[1], version: m[2], portee: 'run', direct: true });
  }
  return dedoublonner(res);
}

export function lirePoetry(texte) {
  const res = [];
  for (const bloc of texte.split(/\n(?=\[\[package\]\])/)) {
    if (!bloc.startsWith('[[package]]')) continue;
    const nom = /^name\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    const cat = /^category\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    if (nom && version) res.push({ type: 'pypi', nom, version, portee: cat === 'dev' ? 'dev' : 'run', direct: false });
  }
  return dedoublonner(res);
}
