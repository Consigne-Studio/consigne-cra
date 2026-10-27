// go.mod : blocs require, avec le marqueur // indirect.
import { dedoublonner } from './npm.js';

export function lireGo(texte) {
  const res = [];
  let dansBloc = false;
  for (const brut of texte.split(/\r?\n/)) {
    const l = brut.trim();
    if (/^require\s*\($/.test(l)) { dansBloc = true; continue; }
    if (dansBloc && l === ')') { dansBloc = false; continue; }
    const m = dansBloc ? /^(\S+)\s+(v\S+)(.*)$/.exec(l) : /^require\s+(\S+)\s+(v\S+)(.*)$/.exec(l);
    if (m) res.push({ type: 'golang', nom: m[1], version: m[2], portee: 'run', direct: !/\/\/\s*indirect/.test(m[3]) });
  }
  return dedoublonner(res);
}
