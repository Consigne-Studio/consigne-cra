// package-lock.json / npm-shrinkwrap.json, versions 1 à 3.
export function lireNpm(texte) {
  const lock = JSON.parse(texte);
  const res = [];
  const racine = lock.packages?.[''] || {};
  const directs = new Set([
    ...Object.keys(racine.dependencies || {}),
    ...Object.keys(racine.devDependencies || {}),
    ...Object.keys(racine.optionalDependencies || {}),
  ]);
  if (lock.packages) {
    for (const [cle, p] of Object.entries(lock.packages)) {
      if (!cle || p.link || !p.version) continue;
      const i = cle.lastIndexOf('node_modules/');
      if (i < 0) continue; // espaces de travail (workspaces) : pas des dépendances
      const nom = p.name || cle.slice(i + 'node_modules/'.length);
      const direct = cle === `node_modules/${nom}` && directs.has(nom);
      res.push({ type: 'npm', nom, version: p.version, portee: p.dev ? 'dev' : 'run', direct, integrite: p.integrity || null });
    }
  } else if (lock.dependencies) {
    const visiter = (deps, niveau) => {
      for (const [nom, p] of Object.entries(deps)) {
        if (p.version && !p.version.startsWith('file:')) {
          res.push({ type: 'npm', nom, version: p.version, portee: p.dev ? 'dev' : 'run', direct: niveau === 0, integrite: p.integrity || null });
        }
        if (p.dependencies) visiter(p.dependencies, niveau + 1);
      }
    };
    visiter(lock.dependencies, 0);
  }
  return dedoublonner(res);
}

export function dedoublonner(liste) {
  const vus = new Map();
  for (const c of liste) {
    const cle = `${c.type}|${c.nom}|${c.version}`;
    const avant = vus.get(cle);
    if (!avant) vus.set(cle, { ...c });
    else {
      avant.direct = avant.direct || c.direct;
      if (c.portee === 'run') avant.portee = 'run';
    }
  }
  return [...vus.values()];
}
