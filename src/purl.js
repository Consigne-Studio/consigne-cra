// Construction et lecture des Package URL (https://github.com/package-url/purl-spec).

const TYPES = {
  npm: 'npm', nuget: 'nuget', pypi: 'pypi', cargo: 'cargo', golang: 'golang',
  composer: 'composer', maven: 'maven', generic: 'generic',
};

// Écosystème OSV correspondant à chaque type purl.
export const ECOSYSTEME_OSV = {
  npm: 'npm', nuget: 'NuGet', pypi: 'PyPI', cargo: 'crates.io', golang: 'Go',
  composer: 'Packagist', maven: 'Maven',
};

const enc = (s) => encodeURIComponent(s).replace(/%3A/g, ':');

export function purl(type, nom, version, espace) {
  if (!TYPES[type]) throw new Error(`Type purl inconnu : ${type}`);
  let ns = espace;
  let n = nom;
  if (type === 'npm' && nom.startsWith('@')) {
    [ns, n] = nom.split('/');
  }
  if (type === 'pypi') n = nom.toLowerCase().replace(/[-_.]+/g, '-');
  if ((type === 'golang' || type === 'composer') && nom.includes('/')) {
    const i = nom.lastIndexOf('/');
    ns = nom.slice(0, i);
    n = nom.slice(i + 1);
  }
  if (type === 'maven' && nom.includes(':')) [ns, n] = nom.split(':');
  const nsPart = ns ? ns.split('/').map(enc).join('/') + '/' : '';
  return `pkg:${type}/${nsPart}${enc(n)}${version ? '@' + enc(version) : ''}`;
}

export function lirePurl(p) {
  const m = /^pkg:([a-z]+)\/(.+?)(?:@([^?#]+))?(?:[?#].*)?$/.exec(p || '');
  if (!m) return null;
  const type = m[1];
  const chemin = m[2].split('/').map(decodeURIComponent);
  const nomCourt = chemin.pop();
  const ns = chemin.join('/');
  let nom = nomCourt;
  if (ns) nom = type === 'maven' ? `${ns}:${nomCourt}` : `${ns}/${nomCourt}`;
  return { type, espace: ns || null, nom, version: m[3] ? decodeURIComponent(m[3]) : null };
}
