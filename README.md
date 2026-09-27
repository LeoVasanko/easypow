# Easy PoW for Web Apps

A defense for web services against bots and other spam. A proof-of-work CAPTCHA asks a browser to perform a small amount of computation before a request is accepted. This can be used to reduce automated abuse by making high-volume requests more costly to them. EasyPoW is intended for Python backends that issue proof-of-work challenges to browser clients and verify the returned solutions.

```sh
uv add easypow
```

The basic flow is that the server creates a challenge, that is sent to client, and the client responds with the solution, and after validation we allow their original request to proceed.

## Python backend

```python
import easypow

# Within your WebSocket handler:
challenge = easypow.generate(5.0)      # ~seconds to solve
await ws.send_text(challenge)
# Client runs JS:                        solution = await solve(challenge)
solution = await ws.receive_text()
easypow.validate(challenge, solution)  # raises ValueError if invalid
```

The same can be adapted to any protocol you have, of course, while maintaining some way of keeping the challenge on server, making sure that clients cannot use the same one more than once. WebSockets are particularly useful because we can simply keep challenge in a local variable and do the dance only when the socket is first connected, and then continuing without any further verifications through the ordinary chat your application would do.

Also useful is to start calculating in the background, and submit a response with the next command that requires PoW. This way the verification can happen without disturbing the user, if he spends at least that time filling up a form or whatever activity it is you wish to protect.

## JavaScript solver

Download [easypow.js](https://git.zi.fi/LeoVasanko/easypow/raw/branch/main/easypow/easypow.js) module to your project. If needed programmatically, this is also available from the Python module as `easypow.js` string or via CLI.

It provides `solve` both as a named and as the default export:

```js
import solve from './easypow.js'

const solution = await solve(challenge)  // optional AbortSignal as 2nd arg
```

### Plain function version

If it better suits you, the entire solution function can be copied from here to where ever you need it.

```js
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
```

## CLI

Run via `python -m easypow <command> <args>`. Supported commands are **generate**, **validate**, **solve** and **js**, corresponding to the Python API. No console scripts are installed because this module is mainly intended to be used via Python API by other software that might not want such pollution.

## Design principles

Many proof-of-work schemes use an exponential difficulty measure: for example, the number of initial zero bits required in a hash. Each additional bit roughly doubles the expected work, which gives rather coarse control over difficulty. The search is also inherently random and memoryless. If a challenge is expected to take 5 seconds and 10 seconds have already passed without a solution, the expected remaining time is still about 5 seconds. An unlucky solve can therefore take much longer than intended.

To make the work both finer-grained and more predictable, we use smaller rounds and require several of them to be solved. A basic round takes about 0.1 seconds on the target machine, but with large random variation. Requiring 10 independent rounds still gives about 1 second of expected work, while averaging out much of that randomness: the total time is considerably more concentrated around 1 second than a single harder 1-second search. The solution contains the nonce found for each round, and the server verifies them individually.

This also separates two useful controls. The zero-bit requirement determines the asymmetry between solving and verification, while the number of required rounds controls total work approximately linearly. Difficulty can therefore be adjusted in small time increments without weakening the basic solve/verify ratio.

Verification itself must be cheap in two ways. First, invalid submissions must not be able to consume substantial server resources: an attacker can always send arbitrary solutions without doing any work. Second, producing a valid solution must be much more expensive than checking one.

Checking a candidate still requires performing the underlying cryptographic operation, so that operation cannot be made arbitrarily expensive. Conversely, if it is made too cheap and the difficulty is moved entirely into requiring more zero bits, JavaScript overhead and other supporting machinery begin to dominate, making browser performance much worse than native code. The implementation therefore uses PBKDF2-SHA512 through Web Crypto with 128 iterations. That would be extremely low for password hashing, but here it places each trial in a useful range: expensive enough that native cryptographic execution dominates, while still cheap for the server to verify.

With the minimal zero-bit requirement, producing a valid round costs 2048 times as much expected work as verifying one candidate. Because a complete solution consists of a sequence of valid rounds, the server can stop at the first failure. Random or fabricated submissions therefore normally cost only a single cheap verification, while a valid solution requires the client to have paid the full proof-of-work cost. Larger work factors increase this asymmetry further because we require a higher number of zero bits while keeping the round count restrained.

Finally, we wish the function be abortable, while allowing the browser to keep running. AbortSignals produce a useful mechanism for external termination, but checking for the signal is expensive. The current implementation checks this between rounds only, and for that reason also we wish to keep the basic round fairly quick. This scales well from 0.1s to a few minutes expected cost in the current implementation. For the sake of simplicity, we did not implement further break points or infinite scaling.
