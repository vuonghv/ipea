/*
 * IP Encryption and Authentication Protocol
 *
 * Author: Vuong Hoang <vuonghv.cs@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _IPEA_IPEA_H
#define _IPEA_IPEA_H

#include <linux/types.h>
#include <linux/skbuff.h>

#define LICENSE "GPL"
#define ALIAS "ipea"
#define DRIVER_AUTHOR "Vuong Hoang <vuonghv.cs@gmail.com>"
#define DRIVER_DESC "IP Encryption and Authentication Protocol"

/* This IP number in the Protocol field of the IPv4 */
#define IPEA_PROTOCOL_NUMBER 0xEE
#define IPEA_MAC_SIZE 20    /* HMAC(SHA1) */
#define IPEA_ENCRYPT_BLOCKSIZE 16 /* AES */
#define IPEA_ENC_MAX_KEYSIZE 32
#define IPEA_HMAC_MAX_KEYSIZE 32

#define AES_BLOCK_SIZE  16
#define AES_128_KEYSIZE 16
#define AES_192_KEYSIZE 24
#define AES_256_KEYSIZE 32

#define HMAC_KEY_SIZE 20

enum CRYPTO_ALG {
    CRYPTO_AES_128,
    CRYPTO_AES_192,
    CRYPTO_AES_256
};

enum CRYPTO_MODE {
    CBC, CTR
};

/* Currently, only support AES-CBC */
struct ipea_key {
    size_t ekeylen;
    size_t hkeylen;
    u8 ekey[IPEA_ENC_MAX_KEYSIZE]; /* encryption key */
    u8 iv[AES_BLOCK_SIZE];       /* init vector for CBC mode */
    u8 hkey[IPEA_HMAC_MAX_KEYSIZE]; /* hmac key */
};

struct ipea_hdr {
    u8 enc_alg; /* Encryption algorithm used */
    u8 mode;
    u8 protocol; /* saved the protocol field of IP header */
};

/* Encrypt the IP-packet's payload by using AES-CBC
 * then hash the packet by using HMAC-SHA1
 * exclude TTL, DSCP, Header Checksum
 */
int ipea_encrypt_mac(struct sk_buff *skb,
                     const struct ipea_hdr *ea_hdr,
                     const struct ipea_key *ipkey);

/* Verify the IP-packet
 * return true if the packet is valid, otherwise false
 */
bool ipea_valid(struct sk_buff *skb, const struct ipea_key *ipeakey);

int ipea_decrypt(struct sk_buff *skb, const struct ipea_key *ipkey);

#endif  /* _IPEA_IPEA_H */
