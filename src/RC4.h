#ifndef RC4_H 
#define RC4_H

#include <linux/types.h>

/**
 * rc4 - RC4 stream cipher encryption/decryption
 * @plaintext: Input data to encrypt/decrypt
 * @key: Encryption key
 * @ciphertext: Output buffer for encrypted/decrypted data
 * @data_len: Length of input data
 * @key_len: Length of encryption key
 *
 * Note: RC4 is symmetric, so encryption and decryption use the same function.
 * WARNING: RC4 is cryptographically broken and should not be used in production.
 * This implementation is for educational purposes only.
 */
void rc4(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext,
         size_t data_len, size_t key_len);

#endif // RC4_H
