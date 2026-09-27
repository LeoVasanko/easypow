async function solve(challenge, signal) {
  const B64URL = { alphabet: 'base64url', omitPadding: true }
  const c = Uint8Array.fromBase64(challenge, B64URL)
  const key = await crypto.subtle.importKey('raw', c, 'PBKDF2', false, ['deriveBits'])
  const salt = new Uint32Array(1)
  const args = { name: 'PBKDF2', salt, iterations: 1 << (c[1] & 0xF), hash: 'SHA-512' }
  const mask = (1 << (c[1] >> 4)) - 1
  const fragments = []
  for (let w=c[0]; w-->0;) {
    if (signal?.aborted) throw new DOMException('PoW operation aborted', 'AbortError')
    do {
      ++salt[0]
    } while (new Uint32Array(await crypto.subtle.deriveBits(args, key, 32))[0] & mask)
    fragments.push(new Uint8Array(salt.buffer).toBase64(B64URL).replace(/A+$/, ''))
  }
  return fragments.join('.')
}

export { solve, solve as default }
