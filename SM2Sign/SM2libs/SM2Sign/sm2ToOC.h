//
//  sm2ToOC.h
//  SM2OC
//
//  Created by 九州云腾 on 2018/4/20.
//  Copyright © 2018年 九州云腾. All rights reserved.
//

#ifndef sm2ToOC_h
#define sm2ToOC_h

#include <stdio.h>
#include "ec.h"

EC_GROUP *new_ec_group(int is_prime_field,
                       const char *p_hex, const char *a_hex, const char *b_hex,
                       const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex);

 int JZYT_sm2_sign(const EC_GROUP *group,
                         const char *sk, const char *xP, const char *yP,
                         const char *id, const char *Z,
                         const char *M, const char *e,
                         const char *k, const char *r, const char *s,unsigned char * signedData, unsigned long * pulSigLen);

int JZYT_sm2_verify(const EC_GROUP *group,
                const char *sk, const char *xP, const char *yP,
                const char *id,const char *M,unsigned char sig[256],unsigned int siglen);

#endif /* sm2ToOC_h */
