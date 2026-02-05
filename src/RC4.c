#include "RC4.h"
#include <linux/kernel.h>
#include <linux/string.h>

#define RC_SIZE 256

/**
 * rc4 - RC4 stream cipher implementation
 * 
 * This is a symmetric stream cipher - the same function is used for both
 * encryption and decryption. RC4 works by generating a pseudo-random
 * keystream that is XORed with the plaintext.
 *
 * Security Note: RC4 has known vulnerabilities and is deprecated for
 * cryptographic use. This implementation is for educational purposes only.
 */
void rc4(unsigned char *p, unsigned char *k, unsigned char *c, size_t l, size_t kl)
{
    unsigned char s[RC_SIZE];
    unsigned char t[RC_SIZE];
    unsigned char temp;
    unsigned char kk;
    size_t i, j, x;

    /* Key-Scheduling Algorithm (KSA) */
    for (i = 0; i < RC_SIZE; i++) {
        s[i] = i;
        t[i] = k[i % kl];
    }

    j = 0;
    for (i = 0; i < RC_SIZE; i++) {
        j = (j + s[i] + t[i]) % RC_SIZE;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    /* Pseudo-Random Generation Algorithm (PRGA) */
    i = 0;
    j = 0;
    for (x = 0; x < l; x++) {
        i = (i + 1) % RC_SIZE;
        j = (j + s[i]) % RC_SIZE;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        kk = s[(s[i] + s[j]) % RC_SIZE];
        c[x] = p[x] ^ kk;
    }

    /* Zero out sensitive data from stack */
    memset(s, 0, sizeof(s));
    memset(t, 0, sizeof(t));
}
