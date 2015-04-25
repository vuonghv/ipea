/*
 * Utility functions for IPEA
 *
 * Author: Vuong Hoang <vuonghv.cs@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef _IPEA_UTILITY_H
#define _IPEA_UTILITY_H

#include <linux/types.h>
#include <linux/printk.h>

#define AES_CBC_ENC 0
#define AES_CBC_DEC 1

int __aes_cbc_crypt(unsigned int type,
        u8 *in, size_t len,
        u8 const *key, size_t keysize,
        u8 const *iv, u8 *out);

/*
 * aes_cbc_encrypt - Encryption function using cbc(aes)
 * @in: buffer held the plaintext
 * @len: length of buffer
 * @key: buffer held the AES key
 * @keysize: key's size
 * @iv: init vector
 * @out: buffer held the ciphertext
 *
 * This function uses AES cipher with CBC mode,
 * support in-place encryption where in and out point
 * the same memory.
 */
inline int aes_cbc_encrypt(u8 *in, size_t len,
            u8 const *key, size_t keysize,
            u8 const *iv, u8 *out)
{
    return __aes_cbc_crypt(AES_CBC_ENC, in, len,
                            key, keysize, iv, out);
}

/*
 * aes_cbc_decrypt - Decryption function using cbc(aes)
 * @in: buffer held the plaintext
 * @len: length of buffer
 * @key: buffer held the AES key
 * @keysize: key's size
 * @iv: init vector
 * @out: buffer held the ciphertext
 *
 * This function uses AES cipher with CBC mode,
 * support in-place decryption where in and out point
 * the same memory.
 */
inline int aes_cbc_decrypt(u8 *in, size_t len,
            u8 const *key, size_t keysize,
            u8 const *iv, u8 *out)
{
    return __aes_cbc_crypt(AES_CBC_DEC, in, len,
                            key, keysize, iv, out);
}

int hmac(const char *alg_name,
        const u8 *key, size_t keysize,
        const u8 *in, size_t len, u8 *out);

inline int hmac_sha1(const u8 *key, size_t keysize,
                    const u8 *in, size_t len, u8 *out) {
    return hmac("hmac(sha1)", key, keysize, in, len, out);
}

inline void print_hex(const u8 *buf, size_t len) {
    for (int i = 0; i < len; ++i)
        printk("%02x", buf[i]);
    printk("\n");
}

#endif  /* _IPEA_UTILITY_H */
