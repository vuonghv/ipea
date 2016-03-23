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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h> /* ip_send_check, ip_rcv ...*/
#include <linux/moduleparam.h>
#include <linux/string.h>
#include "utility.h"
#include "ipea.h"

static struct ipea_key ipeakey;
static struct ipea_hdr ipeah;
static struct nf_hook_ops post_rout_ops;    /* NF_IP_LOCAL_OUT */
static struct nf_hook_ops pre_rout_ops;   /* NF_IP_PRE_ROUTING */

static u8 src_addr[4] = {127, 0, 0, 1};  /* source ip address */
static u8 dst_addr[4] = {127, 0, 0, 1};  /* destination ip address */
static u8 enc_key[IPEA_ENC_MAX_KEYSIZE];    /* encryption key */
static u8 iv[AES_BLOCK_SIZE];   /* initial vector */
static u8 hmac_key[IPEA_HMAC_MAX_KEYSIZE];

module_param_array(src_addr, byte, NULL, 0000);
MODULE_PARM_DESC(src_addr, "source IP address");

module_param_array(dst_addr, byte, NULL, 0000);
MODULE_PARM_DESC(dst_addr, "destination IP address");

module_param_string(enc_key, enc_key, IPEA_ENC_MAX_KEYSIZE, 0000);
MODULE_PARM_DESC(enc_key, "private encryption key");

module_param_string(iv, iv, AES_BLOCK_SIZE, 0000);
MODULE_PARM_DESC(iv, "initial vector");

module_param_string(hmac_key, hmac_key, IPEA_HMAC_MAX_KEYSIZE, 0000);
MODULE_PARM_DESC(hmac_key, "hmac key");

/* Get random values for ipea_key */
static void init_ipea_key(struct ipea_key *ipkey,
                          size_t ekeylen,
                          size_t hkeylen)
{
    ipkey->ekeylen = (ekeylen > IPEA_ENC_MAX_KEYSIZE ?
                            IPEA_ENC_MAX_KEYSIZE : ekeylen);
    ipkey->hkeylen = (hkeylen > IPEA_HMAC_MAX_KEYSIZE ?
                            IPEA_HMAC_MAX_KEYSIZE : hkeylen);

    get_random_bytes(ipkey->ekey, ipkey->ekeylen);
    get_random_bytes(ipkey->iv, sizeof(ipkey->iv));
    get_random_bytes(ipkey->hkey, ipkey->hkeylen);
}

int ipea_encrypt_mac(struct sk_buff *skb,
                     const struct ipea_hdr *ipeah,
                     const struct ipea_key *ipeakey)
{
    /* currently, only protocol only supports encryption and integrity
     * on linear buffer socket buffer
     */
    if (skb_is_nonlinear(skb)) {
        return 0;

    }

    struct iphdr *iph = ip_hdr(skb);
    size_t payload_len = ntohs(iph->tot_len) - iph->ihl * 4;
    int pad = IPEA_ENCRYPT_BLOCKSIZE - (payload_len % IPEA_ENCRYPT_BLOCKSIZE);
    int ret = -EFAULT;

    /* Nead more tail room to add data */
    u16 expand = sizeof(struct ipea_hdr) + pad + IPEA_MAC_SIZE;
    if (expand > skb_tailroom(skb)) {
        ret = pskb_expand_head(skb, 0, expand, GFP_KERNEL);
        printk("Expanded the tailrom\n");
        if (ret < 0) {
            printk(KERN_ERR "Could not expand more room for sk_buff\n");
            return ret;
        }
    }
    skb_put(skb, expand);

    /* payload points to data carried by IP packet
     * need to update headers after expanding
     */
    iph = ip_hdr(skb);
    unsigned char *payload = skb_network_header(skb) + iph->ihl * 4;

    /* padding payload such that multiples of blocks */
    for (int i = 0; i < pad; ++i) {
        payload[payload_len + i] = (unsigned char) pad;
    }

#ifdef __DEBUG
    int padded_len = payload_len + pad;
    printk(KERN_INFO "IP's payload (%d bytes, after padding):\n", padded_len);
    print_hex(payload, padded_len);
#endif

    /* Encrypt payload of IP packet
     * and reserve room for ipea_hdr
     */
    aes_cbc_encrypt(payload, payload_len + pad, ipeakey->ekey, ipeakey->ekeylen,
                    ipeakey->iv, payload + sizeof(struct ipea_hdr)); 

    /* Adding IPEA header */
    struct ipea_hdr *ipeahdr;
    ipeahdr = (struct ipea_hdr *)(skb_network_header(skb) +
                                skb_network_header_len(skb));
    ipeahdr->enc_alg = ipeah->enc_alg;
    ipeahdr->mode = ipeah->mode;
    ipeahdr->protocol = iph->protocol;

    /* Update IP header, recompute checksum */
    iph->protocol = IPEA_PROTOCOL_NUMBER; /* Sign of IPEA protocol */
    /*
     * BE CAREFUL!
     * This operator can make a FATAL OVERNUMBER bug.
     *      iph->tot_len += htons(expand);
     * example:
     *      tot_len: 1508 (05E4 - in memory)
     *      expand :   39 (0027 - in memory)
     * But, after executing:
     *      tot_len += expand ==> tot_len: 1291 (instead of 1547)
     * So why do that happen? answer:
     * iph->tot_len (__be16) so its value is saved 05E4 in memory
     * htons(expand) (__be16) saved 0027 in memory as well.
     * When you call: tot_len += htons(expand);
     * In Intel CPU with litle endian, 05E4 => 58373 (decimal)
     *                                 0027 =>  9984 (decimal)
     * tot_len = 58373 + 9984 = 68357 (10B05)
     * 0B05 (__be16 in memory: 1291)
     *
     * So for all litle-endian CPU, you should covert all __beXX type
     * to __XX. Then execute operator on them, finally, covert __XX
     * variables back to __beXX.
     */
    u16 tot_len = ntohs(iph->tot_len) + expand;
    iph->tot_len = htons(tot_len);
    ip_send_check(iph);   /* recompute IP checksum */
    
    /* Compute HMAC-SHA1, appended at the end of IP payload
     * Back up modified fields in IP header
     * and set this fields to 0
     * Finally, compute HMAC on whole IP packet
     */
    u8 ttl = iph->ttl;
    u8 tos = iph->tos;
    __sum16 csum = iph->check;
    
    iph->ttl = 0;
    iph->tos = 0;
    iph->check = 0;
    
    hmac_sha1(ipeakey->hkey, ipeakey->hkeylen, (u8 *)iph, 
            ntohs(iph->tot_len) - IPEA_MAC_SIZE,
            (u8 *)iph + ntohs(iph->tot_len) - IPEA_MAC_SIZE);

    /* Update IP header */
    iph->ttl = ttl;
    iph->tos = tos;
    iph->check = csum;

#ifdef __DEBUG
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4;
    printk(KERN_INFO "IP's payload (%d bytes, after encrypting and mac):\n",
            payload_len);
    print_hex(payload, payload_len);
#endif
    return 0;
}

bool ipea_valid(struct sk_buff *skb, const struct ipea_key *ipeakey)
{
    struct iphdr *iph;
    u8 *digest;
    u8 *ip_mac;
    bool ret;

    /* Just verify mac in IPEA protocol */
    iph = ip_hdr(skb);
    if (iph->protocol != IPEA_PROTOCOL_NUMBER) {
        return true;
    }

    digest = (u8 *)kmalloc(IPEA_MAC_SIZE, GFP_KERNEL);
    if (!digest) {
        printk(KERN_ERR "Out of memory (in function %s)\n", __func__);
        return false;
    }

    /* Backup modified fields */
    u8 ttl = iph->ttl;
    u8 tos = iph->tos;
    __sum16 check = iph->check;

    iph->ttl = 0;
    iph->tos = 0;
    iph->check = 0;

    hmac("hmac(sha1)", ipeakey->hkey, ipeakey->hkeylen,
            (u8 *)iph, ntohs(iph->tot_len) - IPEA_MAC_SIZE, digest);
    /* Recovery the fields */
    iph->ttl = ttl;
    iph->tos = tos;
    iph->check = check;

    /* Verify */
    ret = true;
    ip_mac = (u8 *)iph + ntohs(iph->tot_len) - IPEA_MAC_SIZE;
    for (int i = 0; i < IPEA_MAC_SIZE; ++i) {
        if (ip_mac[i] != digest[i]) {
            ret = false;
            break;
        }
    }

    /* Update IP header */
    u16 tot_len = ntohs(iph->tot_len) - IPEA_MAC_SIZE;
    iph->tot_len = htons(tot_len);
    ip_send_check(iph);

    /* Trim MAC data, then update IP packet
     * Currently, just consider non-paged packet
     */
    //skb_trim(skb, skb->len - IPEA_MAC_SIZE);
    pskb_trim_rcsum(skb, skb->len - IPEA_MAC_SIZE);

    kfree(digest);
    return ret;
}

int ipea_decrypt(struct sk_buff *skb, const struct ipea_key *ipeakey)
{
    struct iphdr *iph = ip_hdr(skb);
    
    if (iph->protocol != IPEA_PROTOCOL_NUMBER) {
        return 0;
    }

    struct ipea_hdr *ipeah;
    size_t ipeah_size = sizeof(struct ipea_hdr);
    size_t iph_size = skb_network_header_len(skb);

    ipeah = (struct ipea_hdr *)((unsigned char *)iph + iph_size);
    iph->protocol = ipeah->protocol; /* recovery protocol */

    aes_cbc_decrypt((u8 *)iph + iph_size + ipeah_size,
      ntohs(iph->tot_len) - iph_size - ipeah_size,
      ipeakey->ekey, ipeakey->ekeylen,
      ipeakey->iv, (u8 *)iph + iph_size);

    u8 pad = *((u8 *)iph + ntohs(iph->tot_len) - ipeah_size - 1);

    /* Update IP header */
    u16 tot_len = ntohs(iph->tot_len) - ipeah_size - pad;
    iph->tot_len = htons(tot_len);
    ip_send_check(iph);

    /* Trim space for IPEA header and padding data
     * notice that currently, just work on NON-paged packet
     */
    //skb_trim(skb, skb->len - ipeah_size - pad);
    pskb_trim_rcsum(skb, skb->len - ipeah_size - pad);
    
#ifdef __DEBUG
    int payload_len = ntohs(iph->tot_len) - iph->ihl * 4;
    u8 *payload = (u8 *)iph + iph->ihl * 4;
    printk(KERN_INFO "IP's payload (%d bytes, after decrypting):\n",
            payload_len);
    print_hex(payload, payload_len);
    printk("\n");
#endif

    return 0;
}

/* Hooknum: NF_INET_POST_ROUTING */
static unsigned int ipea_out_hook(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    /* We don't want any NULL pointers in the chain to 
     * the IP header.*/
    if (!skb)
        return NF_ACCEPT;
    if (skb_network_header_len(skb) == 0)
        return NF_ACCEPT;

    struct iphdr *iph = ip_hdr(skb);
    /* only use IPEA for local host */
    if (iph->saddr == iph->daddr) {
        ipea_encrypt_mac(skb, &ipeah, &ipeakey);
    }

    return NF_ACCEPT;
}

/* Hooknum: NF_INET_PRE_ROUTING */
static unsigned int ipea_in_hook(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    if (!skb)
        return NF_ACCEPT;
    if (skb_network_header_len(skb) == 0)
        return NF_ACCEPT;

    struct iphdr *iph = ip_hdr(skb);
    /* Ignore any packets not using IPEA protocol */
    if (iph->protocol != IPEA_PROTOCOL_NUMBER) {
        return NF_ACCEPT;
    }

    /* Check integrity of the IP packet
     * Drop it if it has been modified
     */
    if (!ipea_valid(skb, &ipeakey)) {
        printk("Packet is not valid!\n");
        return NF_DROP;
    }

    /* Decrypt the packet to get the original packet */
    ipea_decrypt(skb, &ipeakey);
    return NF_ACCEPT;
}

static int __init ipea_module_init(void)
{
    /* Init IPEA header */
    ipeah.enc_alg = CRYPTO_AES_128;
    ipeah.mode = CBC;
    ipeah.protocol = 0;

    /* Set up IPEA key */
    ipeakey.ekeylen = AES_128_KEYSIZE;
    ipeakey.hkeylen = HMAC_KEY_SIZE;
    memcpy(ipeakey.ekey, enc_key, IPEA_ENC_MAX_KEYSIZE);
    memcpy(ipeakey.hkey, hmac_key, IPEA_HMAC_MAX_KEYSIZE);

    post_rout_ops.hook = ipea_out_hook;
    post_rout_ops.pf = PF_INET;
    post_rout_ops.hooknum = NF_INET_POST_ROUTING;
    post_rout_ops.priority = NF_IP_PRI_FIRST;

    pre_rout_ops.hook = ipea_in_hook;
    pre_rout_ops.pf = PF_INET;
    pre_rout_ops.hooknum = NF_INET_PRE_ROUTING;
    pre_rout_ops.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&post_rout_ops);
    nf_register_hook(&pre_rout_ops);

    /* Display some parameters of protocol */
    printk(KERN_INFO "MODULE IPEA INIT\n");
    printk(KERN_INFO "Enc key : ");
    print_hex(ipeakey.ekey, ipeakey.ekeylen);
    printk(KERN_INFO "IV      : ");
    print_hex(ipeakey.iv, IPEA_ENCRYPT_BLOCKSIZE);
    printk(KERN_INFO "Hmac Key: ");
    print_hex(ipeakey.hkey, ipeakey.hkeylen);
    return 0;
}

static void __exit ipea_module_exit(void)
{
    nf_unregister_hook(&post_rout_ops);
    nf_unregister_hook(&pre_rout_ops);
    printk(KERN_INFO"MODULE IPEA EXIT\n");
}

module_init(ipea_module_init);
module_exit(ipea_module_exit);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS(ALIAS);
