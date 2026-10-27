// Lecteur ZIP minimal (répertoire central, méthodes 0 et 8) pour les archives OSV hors ligne.
import zlib from 'node:zlib';

export function* entreesZip(buf) {
  let fin = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { fin = i; break; }
  }
  if (fin < 0) throw new Error('Archive ZIP invalide : fin de répertoire central introuvable.');
  let n = buf.readUInt16LE(fin + 10);
  let pos = buf.readUInt32LE(fin + 16);
  // ZIP64 : les archives OSV complètes peuvent dépasser 65 535 entrées.
  if (n === 0xffff || pos === 0xffffffff) {
    const loc = fin - 20;
    if (loc >= 0 && buf.readUInt32LE(loc) === 0x07064b50) {
      const fin64 = Number(buf.readBigUInt64LE(loc + 8));
      n = Number(buf.readBigUInt64LE(fin64 + 32));
      pos = Number(buf.readBigUInt64LE(fin64 + 48));
    }
  }
  for (let k = 0; k < n; k++) {
    if (buf.readUInt32LE(pos) !== 0x02014b50) throw new Error('Archive ZIP invalide : entrée du répertoire central attendue.');
    const methode = buf.readUInt16LE(pos + 10);
    let taille = buf.readUInt32LE(pos + 20);
    const lNom = buf.readUInt16LE(pos + 28);
    const lExtra = buf.readUInt16LE(pos + 30);
    const lCom = buf.readUInt16LE(pos + 32);
    let local = buf.readUInt32LE(pos + 42);
    const nom = buf.toString('utf8', pos + 46, pos + 46 + lNom);
    if (taille === 0xffffffff || local === 0xffffffff) {
      let e = pos + 46 + lNom;
      const finExtra = e + lExtra;
      while (e < finExtra) {
        const id = buf.readUInt16LE(e);
        const t = buf.readUInt16LE(e + 2);
        if (id === 1) {
          let q = e + 4;
          if (buf.readUInt32LE(pos + 24) === 0xffffffff) q += 8;
          if (taille === 0xffffffff) { taille = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (local === 0xffffffff) local = Number(buf.readBigUInt64LE(q));
        }
        e += 4 + t;
      }
    }
    pos += 46 + lNom + lExtra + lCom;
    if (nom.endsWith('/')) continue;
    const debut = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const brut = buf.subarray(debut, debut + taille);
    yield { nom, lire: () => (methode === 0 ? brut : methode === 8 ? zlib.inflateRawSync(brut) : null) };
  }
}
