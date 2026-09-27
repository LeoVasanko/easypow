/* Proof-of-Work solver using PBKDF2-HMAC-SHA512, port of solver.js.
 *
 * Usage: solve <challenge>
 *   challenge: 12-char base64url string decoding to 9 bytes:
 *     [0] work w, [1] difficulty (high nibble z = zero bits,
 *     low nibble n = iteration exponent), [2..8] random.
 * Prints the dot-separated base64url solution.
 *
 * Build: cc -O2 -o solve solve.c -lcrypto
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_decode(const char *in, uint8_t *out) {
    size_t len = strlen(in), n = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        const char *p = strchr(B64, in[i]);
        if (!p) { fprintf(stderr, "invalid base64url\n"); exit(1); }
        acc = (acc << 6) | (uint32_t)(p - B64);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[n++] = (uint8_t)(acc >> bits); }
    }
    return n;
}

static void b64url_encode(const uint8_t *in, size_t len, char *out) {
    size_t n = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 6) { bits -= 6; out[n++] = B64[(acc >> bits) & 0x3F]; }
    }
    if (bits) out[n++] = B64[(acc << (6 - bits)) & 0x3F];
    out[n] = '\0';
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: solve <challenge>\n"); return 1; }

    uint8_t c[9];
    if (b64url_decode(argv[1], c) != 9) {
        fprintf(stderr, "challenge must decode to 9 bytes\n");
        return 1;
    }
    unsigned w = c[0], z = c[1] >> 4, iterations = 1u << (c[1] & 0xF);
    uint32_t mask = (1u << z) - 1;

    uint32_t nonce = 0;
    int first = 1;
    while (w--) {
        uint8_t digest[4];
        do {
            nonce++;
            PKCS5_PBKDF2_HMAC((const char *)c, 9, (uint8_t *)&nonce, 4,
                              (int)iterations, EVP_sha512(), 4, digest);
        } while (*(uint32_t *)digest & mask);
        char frag[7];
        b64url_encode((uint8_t *)&nonce, 4, frag);
        size_t len = strlen(frag);
        while (len && frag[len - 1] == 'A') frag[--len] = '\0';
        printf("%s%s", first ? "" : ".", frag);
        first = 0;
    }
    printf("\n");
    return 0;
}
