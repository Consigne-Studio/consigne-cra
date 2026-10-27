// Comparaison de versions suffisante pour les plages OSV de type SEMVER et ECOSYSTEM
// (npm, NuGet, crates.io, Go, Packagist, PyPI courant). Les cas exotiques (époques PEP 440,
// qualificatifs Maven) sont traités de façon prudente : en cas de doute, on considère la
// version comme potentiellement affectée plutôt que de taire une vulnérabilité.

function decouper(v) {
  const s = String(v).trim().replace(/^v/i, '').replace(/\+.*$/, '');
  const m = /^([0-9]+(?:\.[0-9]+)*)(.*)$/.exec(s);
  if (!m) return { nums: [], pre: s ? [s] : [], brut: s };
  const nums = m[1].split('.').map(Number);
  const reste = m[2].replace(/^[-.]/, '');
  // PEP 440 : 1.0rc1, 1.0.post1, 1.0.dev2
  const post = /^post(\d*)$/i.exec(reste);
  if (post) return { nums: [...nums, 0, Number(post[1] || 0)], pre: [], post: true };
  const pre = reste ? reste.split(/[.-]/).filter(Boolean) : [];
  return { nums, pre };
}

function cmpIdent(a, b) {
  const na = /^\d+$/.test(a);
  const nb = /^\d+$/.test(b);
  if (na && nb) return Number(a) - Number(b);
  if (na) return -1;
  if (nb) return 1;
  // dev < alpha < beta < rc pour les identifiants courants
  const rang = (x) => {
    const m = /^(dev|alpha|a|beta|b|rc|c|preview|pre)(\d*)$/i.exec(x);
    if (!m) return null;
    const ordre = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, preview: 2, pre: 2, rc: 3, c: 3 }[m[1].toLowerCase()];
    return [ordre, Number(m[2] || 0)];
  };
  const ra = rang(a);
  const rb = rang(b);
  if (ra && rb) return ra[0] - rb[0] || ra[1] - rb[1];
  return a < b ? -1 : a > b ? 1 : 0;
}

export function comparer(a, b) {
  const A = decouper(a);
  const B = decouper(b);
  const n = Math.max(A.nums.length, B.nums.length);
  for (let i = 0; i < n; i++) {
    const d = (A.nums[i] ?? 0) - (B.nums[i] ?? 0);
    if (d) return Math.sign(d);
  }
  if (!A.pre.length && B.pre.length) return 1;
  if (A.pre.length && !B.pre.length) return -1;
  const m = Math.max(A.pre.length, B.pre.length);
  for (let i = 0; i < m; i++) {
    if (A.pre[i] === undefined) return -1;
    if (B.pre[i] === undefined) return 1;
    const d = cmpIdent(A.pre[i], B.pre[i]);
    if (d) return Math.sign(d);
  }
  return 0;
}

// Évalue une entrée `affected` d'un enregistrement OSV pour une version donnée.
export function versionAffectee(affected, version) {
  if (Array.isArray(affected.versions) && affected.versions.includes(version)) return true;
  for (const plage of affected.ranges || []) {
    if (plage.type === 'GIT') continue;
    const evts = [...(plage.events || [])];
    // Les événements sont évalués dans l'ordre des versions (spécification OSV).
    evts.sort((x, y) => {
      const vx = Object.values(x)[0];
      const vy = Object.values(y)[0];
      if (vx === '0') return -1;
      if (vy === '0') return 1;
      return comparer(vx, vy);
    });
    let dedans = false;
    for (const e of evts) {
      if (e.introduced !== undefined) {
        if (e.introduced === '0' || comparer(version, e.introduced) >= 0) dedans = true;
      } else if (e.fixed !== undefined) {
        if (comparer(version, e.fixed) >= 0) dedans = false;
      } else if (e.last_affected !== undefined) {
        if (comparer(version, e.last_affected) > 0) dedans = false;
      } else if (e.limit !== undefined) {
        if (comparer(version, e.limit) >= 0) dedans = false;
      }
    }
    if (dedans) return true;
  }
  return false;
}

export function versionsCorrectives(affected) {
  const res = new Set();
  for (const plage of affected.ranges || []) {
    if (plage.type === 'GIT') continue;
    for (const e of plage.events || []) if (e.fixed) res.add(e.fixed);
  }
  return [...res];
}
