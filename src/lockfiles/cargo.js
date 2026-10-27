// Cargo.lock : seuls les paquets venant d'un registre sont des dépendances tierces.
import { dedoublonner } from './npm.js';

export function lireCargo(texte) {
  const res = [];
  for (const bloc of texte.split(/\n(?=\[\[package\]\])/)) {
    if (!bloc.startsWith('[[package]]')) continue;
    const nom = /^name\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    const source = /^source\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    const somme = /^checksum\s*=\s*"([^"]+)"/m.exec(bloc)?.[1];
    if (nom && version && source?.startsWith('registry+')) {
      res.push({ type: 'cargo', nom, version, portee: 'run', direct: false, integrite: somme ? `sha256-${somme}` : null });
    }
  }
  return dedoublonner(res);
}
