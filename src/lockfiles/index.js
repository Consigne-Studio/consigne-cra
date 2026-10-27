// Détection et lecture des fichiers de verrouillage. Chaque lecteur renvoie une liste de
// composants { type, nom, version, portee, direct, source } sans doublon.
import fs from 'node:fs';
import path from 'node:path';
import { lireNpm } from './npm.js';
import { lireYarn } from './yarn.js';
import { lirePnpm } from './pnpm.js';
import { lireNuget } from './nuget.js';
import { lireRequirements, lirePoetry } from './pypi.js';
import { lireCargo } from './cargo.js';
import { lireGo } from './go.js';
import { lireComposer } from './composer.js';

export const LECTEURS = [
  { fichier: 'package-lock.json', ecosysteme: 'npm', lire: lireNpm },
  { fichier: 'npm-shrinkwrap.json', ecosysteme: 'npm', lire: lireNpm },
  { fichier: 'yarn.lock', ecosysteme: 'npm', lire: lireYarn },
  { fichier: 'pnpm-lock.yaml', ecosysteme: 'npm', lire: lirePnpm },
  { fichier: 'packages.lock.json', ecosysteme: 'NuGet', lire: lireNuget },
  { fichier: 'requirements.txt', ecosysteme: 'PyPI', lire: lireRequirements },
  { fichier: 'poetry.lock', ecosysteme: 'PyPI', lire: lirePoetry },
  { fichier: 'Cargo.lock', ecosysteme: 'crates.io', lire: lireCargo },
  { fichier: 'go.mod', ecosysteme: 'Go', lire: lireGo },
  { fichier: 'composer.lock', ecosysteme: 'Packagist', lire: lireComposer },
];

const IGNORES = new Set(['node_modules', '.git', 'vendor', 'target', 'bin', 'obj', 'dist', '.venv', 'venv', '__pycache__', 'cra-sortie']);

// Parcourt `racine` (profondeur limitée) et renvoie les fichiers de verrouillage trouvés.
// exclure : chemins relatifs à la racine (dossiers ou fichiers), par exemple un outillage non livré.
export function trouverVerrous(racine, profondeurMax = 4, exclure = []) {
  const trouves = [];
  const exclus = exclure.map((x) => String(x).replace(/\\/g, '/').replace(/^\.\/|\/+$/g, '')).filter(Boolean);
  const estExclu = (chemin) => {
    const rel = path.relative(racine, chemin).split(path.sep).join('/');
    return exclus.some((x) => rel === x || rel.startsWith(`${x}/`));
  };
  const noms = new Map(LECTEURS.map((l) => [l.fichier, l]));
  const visiter = (dir, prof) => {
    let entrees;
    try { entrees = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    const ici = new Set(entrees.filter((e) => e.isFile()).map((e) => e.name));
    for (const e of entrees) {
      if (estExclu(path.join(dir, e.name))) continue;
      if (e.isFile() && noms.has(e.name)) {
        // Un package-lock rend yarn.lock/pnpm-lock redondants dans le même dossier, et inversement.
        if (e.name === 'yarn.lock' && ici.has('package-lock.json')) continue;
        if (e.name === 'pnpm-lock.yaml' && (ici.has('package-lock.json') || ici.has('yarn.lock'))) continue;
        trouves.push({ chemin: path.join(dir, e.name), ...noms.get(e.name) });
      } else if (e.isDirectory() && prof < profondeurMax && !IGNORES.has(e.name) && !e.name.startsWith('.')) {
        visiter(path.join(dir, e.name), prof + 1);
      }
    }
  };
  visiter(racine, 0);
  return trouves.sort((a, b) => a.chemin.localeCompare(b.chemin));
}

export function lireVerrou(entree, racine) {
  const contenu = fs.readFileSync(entree.chemin, 'utf8');
  const relatif = path.relative(racine, entree.chemin).split(path.sep).join('/');
  const composants = entree.lire(contenu, entree.chemin);
  return composants.map((c) => ({ ...c, source: relatif }));
}
