//
//  sm2ToOC.c
//  SM2OC
//
//  Created by 九州云腾 on 2018/4/20.
//  Copyright © 2018年 九州云腾. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
# include "bn.h"
# include "ec.h"
# include "evp.h"
# include "rand.h"
# include "engine.h"
# include "sm2.h"
#include "e_os.h"
#include "string.h"
# include "sm2_lcl.h"
# include "pkcs12.h"
#include "sm2ToOC.h"

# define VERBOSE 1

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

static const char *rnd_number = NULL;
 int fbytes(unsigned char *buf, int num)
{
    int ret = 0;
    BIGNUM *bn = NULL;

    if (!BN_hex2bn(&bn, rnd_number)) {
        goto end;
    }
    if (BN_num_bytes(bn) > num) {
        goto end;
    }
    memset(buf, 0, num);
    if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
        goto end;
    }
    ret = 1;
end:
    BN_free(bn);
    return ret;
}

 int change_rand(const char *hex)
{
    if (!(old_rand = RAND_get_rand_method())) {
        return 0;
    }

    fake_rand.seed        = old_rand->seed;
    fake_rand.cleanup    = old_rand->cleanup;
    fake_rand.add        = old_rand->add;
    fake_rand.status    = old_rand->status;
    fake_rand.bytes        = fbytes;
    fake_rand.pseudorand    = old_rand->bytes;

    if (!RAND_set_rand_method(&fake_rand)) {
        return 0;
    }

    rnd_number = hex;
    return 1;
}

 int restore_rand(void)
{
    rnd_number = NULL;
    if (!RAND_set_rand_method(old_rand))
        return 0;
    else    return 1;
}

 EC_GROUP *new_ec_group(int is_prime_field,
                              const char *p_hex, const char *a_hex, const char *b_hex,
                              const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
    int ok = 0;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *n = NULL;
    BIGNUM *h = NULL;
    EC_POINT *G = NULL;
    point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
    int flag = 0;

    if (!(ctx = BN_CTX_new())) {
        goto err;
    }

    if (!BN_hex2bn(&p, p_hex) ||
        !BN_hex2bn(&a, a_hex) ||
        !BN_hex2bn(&b, b_hex) ||
        !BN_hex2bn(&x, x_hex) ||
        !BN_hex2bn(&y, y_hex) ||
        !BN_hex2bn(&n, n_hex) ||
        !BN_hex2bn(&h, h_hex)) {
        goto err;
    }

    if (is_prime_field) {
        if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
            goto err;
        }
        if (!(G = EC_POINT_new(group))) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
            goto err;
        }
    } else {
        if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
            goto err;
        }
        if (!(G = EC_POINT_new(group))) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
            goto err;
        }
    }

    if (!EC_GROUP_set_generator(group, G, n, h)) {
        goto err;
    }

    EC_GROUP_set_asn1_flag(group, flag);
    EC_GROUP_set_point_conversion_form(group, form);

    ok = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(n);
    BN_free(h);
    EC_POINT_free(G);
    if (!ok && group) {
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

 EC_KEY *new_ec_key(const EC_GROUP *group,
                          const char *sk, const char *xP, const char *yP,
                          const char *id, const EVP_MD *id_md)
{
    int ok = 0;
    EC_KEY *ec_key = NULL;
    BIGNUM *d = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    OPENSSL_assert(group);
    OPENSSL_assert(xP);
    OPENSSL_assert(yP);

    if (!(ec_key = EC_KEY_new())) {
        goto end;
    }
    if (!EC_KEY_set_group(ec_key, group)) {
        goto end;
    }

    if (sk) {
        if (!BN_hex2bn(&d, sk)) {
            goto end;
        }
        if (!EC_KEY_set_private_key(ec_key, d)) {
            goto end;
        }
    }

    if (xP && yP) {
        if (!BN_hex2bn(&x, xP)) {
            goto end;
        }
        if (!BN_hex2bn(&y, yP)) {
            goto end;
        }
        if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
            goto end;
        }
    }
    ok = 1;
end:
    if (d) BN_free(d);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (!ok && ec_key) {
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}
EC_KEY *new_Public_key(const EC_GROUP *group,
                   const char *sk, const char *xP, const char *yP,
                   const char *id, const EVP_MD *id_md)
{
    int ok = 0;
    EC_KEY *ec_key = NULL;
    BIGNUM *d = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    OPENSSL_assert(group);
    OPENSSL_assert(xP);
    OPENSSL_assert(yP);

    if (!(ec_key = EC_KEY_new())) {
        goto end;
    }
    if (!EC_KEY_set_group(ec_key, group)) {
        goto end;
    }
    
    if (xP && yP) {
        if (!BN_hex2bn(&x, xP)) {
            goto end;
        }
        if (!BN_hex2bn(&y, yP)) {
            goto end;
        }
        if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
            goto end;
        }
    }
    ok = 1;
end:
    if (d) BN_free(d);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (!ok && ec_key) {
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}


 int JZYT_sm2_sign(const EC_GROUP *group,
                         const char *sk, const char *xP, const char *yP,
                         const char *id, const char *Z,
                         const char *M, const char *e,
                         const char *k, const char *r, const char *s,unsigned char * signedData, unsigned long * pulSigLen)
{
    int ret = 0;
    int verbose = VERBOSE;
    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();
    int type = NID_undef;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen;
    unsigned char sig[256];
    unsigned int siglen;
    const unsigned char *p;
    EC_KEY *ec_key = NULL;
    EC_KEY *pubkey = NULL;
    ECDSA_SIG *sm2sig = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *ss = NULL;
    const BIGNUM *sig_r;
    const BIGNUM *sig_s;

    change_rand(k);

    if (!(ec_key = new_ec_key(group, sk, xP, yP, id, id_md))) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }

    if (verbose > 1) {
        EC_KEY_print_fp(stdout, ec_key, 4);
    }

    dgstlen = sizeof(dgst);

    if (verbose > 1) {
        int j;
        printf("id=%s\n", id);
        printf("zid(xx):");
        for (j = 0; j < dgstlen; j++) { printf("%02x", dgst[j]); } printf("\n");
    }

    dgstlen = sizeof(dgst);
    if (!SM2_compute_message_digest(id_md, msg_md,
                                    (const unsigned char *)M, strlen(M), id, strlen(id),
                                    dgst, &dgstlen, ec_key)) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }
    //printf("dgst = ");
    for (int i = 0; i<dgstlen; i++)
    {
        if (i %4 ==0)
        {
            printf(" ");
        }
        // printf("%02x", dgst[i]);

    }
    //printf("\n");

    //printf("signData = ");
    /* sign */
    siglen = sizeof(sig);
    if (!SM2_sign(type, dgst, dgstlen, sig, &siglen, ec_key)) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }
    for (int i = 0; i<siglen; i++)
    {
        if (i %4 ==0)
        {
            printf(" ");
        }
       // printf("%02x", sig[i]);
    }
    printf("\n");
    memcpy(signedData, sig, siglen);
    * pulSigLen = siglen;
    p = sig;
    if (!(sm2sig = d2i_ECDSA_SIG(NULL, &p, siglen))) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }

    ECDSA_SIG_get0(sm2sig, &sig_r, &sig_s);
    char *rrrr = BN_bn2hex (sig_r);
    if (rrrr)
    {
        // printf ("number is 0x%s\n", rrrr);
        OPENSSL_free (rrrr);
    }
    char *ssss = BN_bn2hex (sig_s);
    if (ssss)
    {
        // printf ("number is 0x%s\n", ssss);
        OPENSSL_free (ssss);
    }
  ret =  JZYT_sm2_verify(group, sk, xP, yP, id,M,sig, siglen);

    ret = 1;
err:
    restore_rand();
    if (ec_key) EC_KEY_free(ec_key);
    if (pubkey) EC_KEY_free(pubkey);
    if (sm2sig) ECDSA_SIG_free(sm2sig);
    if (rr) BN_free(rr);
    if (ss) BN_free(ss);
    return ret;
}

int JZYT_sm2_verify(const EC_GROUP *group,
                  const char *sk, const char *xP, const char *yP,
                  const char *id,const char *M,unsigned char sig[256],unsigned int siglen)
{
    int ret = 0;
    int verbose = VERBOSE;
    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();
    int type = NID_undef;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen;
    const unsigned char *p;
    EC_KEY *ec_key = NULL;
    EC_KEY *pubkey = NULL;
    ECDSA_SIG *sm2sig = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *ss = NULL;
    const BIGNUM *sig_r;
    const BIGNUM *sig_s;
    if (!(ec_key = new_ec_key(group, NULL, xP, yP, id, id_md))) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);

    }

    if (verbose > 1) {
        EC_KEY_print_fp(stdout, ec_key, 4);
    }

    dgstlen = sizeof(dgst);

    if (!SM2_compute_id_digest(id_md, id, strlen(id), dgst, &dgstlen, ec_key)) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }


    if (verbose > 1) {
        int j;
        //printf("id=%s\n", id);
        //printf("zid(xx):");
        for (j = 0; j < dgstlen; j++) { printf("%02x", dgst[j]); } printf("\n");
    }

    dgstlen = sizeof(dgst);
    if (!SM2_compute_message_digest(id_md, msg_md,
                                    (const unsigned char *)M, strlen(M), id, strlen(id),
                                    dgst, &dgstlen, ec_key)) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);

    }
    // printf("dgst = ");
    for (int i = 0; i<dgstlen; i++)
    {
        if (i %4 ==0)
        {
           // printf(" ");
        }
        // printf("%02x", dgst[i]);

    }
    // printf("\n");

    /* verify */
    if (!(pubkey = new_ec_key(group, NULL, xP, yP, id, id_md))) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }

    if (1 != SM2_verify(type, dgst, dgstlen, sig, siglen, pubkey)) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        goto err;
    }

    ret = 1;
err:
    restore_rand();

    if (pubkey) EC_KEY_free(pubkey);
    if (sm2sig) ECDSA_SIG_free(sm2sig);
    if (rr) BN_free(rr);
    if (ss) BN_free(ss);
    return ret;
}


