// packages.lock.json de NuGet (RestorePackagesWithLockFile).
import { dedoublonner } from './npm.js';

export function lireNuget(texte) {
  const lock = JSON.parse(texte);
  const res = [];
  for (const cible of Object.values(lock.dependencies || {})) {
    for (const [nom, p] of Object.entries(cible)) {
      if (p.type === 'Project' || !p.resolved) continue;
      res.push({ type: 'nuget', nom, version: p.resolved, portee: 'run', direct: p.type === 'Direct', integrite: p.contentHash || null });
    }
  }
  return dedoublonner(res);
}
