/*
 * Author: Vuong Hoang <vuonghv.cs@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "utility.h"
#include "ipea.h"

int __aes_cbc_crypt(unsigned int type,
            u8 *in, size_t len,
            u8 const *key, size_t keysize,
            u8 const *iv, u8 *out)
{
    char *alg_name = "cbc(aes)";
    struct crypto_blkcipher *blkcipher = NULL;
    struct blkcipher_desc desc;
    struct scatterlist sg_in;
    struct scatterlist sg_out;
    int ret = -EFAULT;

    blkcipher = crypto_alloc_blkcipher(alg_name, 0, 0);
    if (IS_ERR(blkcipher)) {
        printk(KERN_ERR"Could not allocate "
                "blkcipher handle for %s\n", alg_name);
        return -PTR_ERR(blkcipher);
    }
    
    if (crypto_blkcipher_setkey(blkcipher, key, keysize)) {
        printk(KERN_ERR"Key could not be set.\n");
        ret = -EAGAIN;
        goto err_setkey;
    }

    unsigned int ivsize = crypto_blkcipher_ivsize(blkcipher);
    if (ivsize) {
        crypto_blkcipher_set_iv(blkcipher, iv, ivsize);
    }

    /* Init scatter/gather list */
    sg_init_one(&sg_in, in, len);
    sg_init_one(&sg_out, out, len);

    /* describe info for the block cipher */
    desc.flags = 0;
    desc.tfm = blkcipher;

    /* Encrypt or Decrypt data */
    if (type == AES_CBC_ENC) {
        crypto_blkcipher_encrypt(&desc, &sg_out, &sg_in, len);
    } else {
        crypto_blkcipher_decrypt(&desc, &sg_out, &sg_in, len);
    }
    ret = 0;

err_setkey:
    crypto_free_blkcipher(blkcipher);
    return ret;
}

int hmac(const char *alg_name,
        const u8 *key, size_t keysize,
        const u8 *in, size_t len, u8 *out)
{
    struct crypto_shash *tfm;
    int ret = 0;

    if (!keysize) {
        return -EINVAL;
    }

    tfm = crypto_alloc_shash(alg_name, 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "crypto_alloc_shash failed: err %ld", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    ret = crypto_shash_setkey(tfm, key, keysize);
    if (ret) {
        printk(KERN_ERR "crypto_shash_setkey failed: err %d", ret);
    } else {
        struct {
            struct shash_desc shash;
            char ctx[crypto_shash_descsize(tfm)];
        } desc;

        desc.shash.tfm = tfm;
        desc.shash.flags = CRYPTO_TFM_REQ_MAY_SLEEP;

        ret = crypto_shash_digest(&desc.shash, in, len, out);
    }

    crypto_free_shash(tfm);
    return ret;
}
