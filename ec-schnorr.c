
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>

#include "scheme.h"
#include "locals.h"


typedef struct ECSNOR_KeyPair ECSNOR_KeyPair;
struct ECSNOR_KeyPair
{
    EC_KEY*         eckey;
    const EC_GROUP* group;
    BIGNUM*         group_order;
    const BIGNUM*   sk;              // private key
    const EC_POINT* PK;              // public key
    int             bytelen_go;
    int             bytelen_point;
};


typedef struct ECSNOR_Sig ECSNOR_Sig;
struct ECSNOR_Sig
{
    BIGNUM*	f;
    BIGNUM*	z;
};


typedef struct ECSNOR_SignSessD0 ECSNOR_SignSessD0;
struct ECSNOR_SignSessD0
{
    BIGNUM*         r;
    EC_POINT*       A;
    unsigned char*  A_bytes_m;
    BIGNUM*			fx;
    unsigned char*  f_bytes;
};


typedef struct ECSNOR_VrfySessD0 ECSNOR_VrfySessD0;
struct ECSNOR_VrfySessD0
{
    unsigned char*  A_bytes_m;
    unsigned char*  f0_bytes;
    BIGNUM*         neg_f;
    BIGNUM*			f0;
    EC_POINT*       A;
};




void ECSNOR_keypair_free(void *obj)
{
    ECSNOR_KeyPair *keypair = (ECSNOR_KeyPair*)obj;
    EC_KEY_free(keypair->eckey);
    BN_free(keypair->group_order);
    free(keypair);
}


void *ECSNOR_keypair_new(int sec)
{
    BIGNUM *w = NULL;
    BIGNUM *group_order = NULL;
    EC_KEY *eckey = NULL;

    ECSNOR_KeyPair *ret = NULL;

    ret = calloc(1, sizeof(ECSNOR_KeyPair));
    if (ret == NULL) goto err;

    switch (sec)
    {
    case 160:
        eckey = EC_KEY_new_by_curve_name(CURVE160);
        break;
    case 192:
        eckey = EC_KEY_new_by_curve_name(CURVE192);
        break;
    case 224:
        eckey = EC_KEY_new_by_curve_name(CURVE224);
        break;
    case 256:
        eckey = EC_KEY_new_by_curve_name(CURVE256);
        break;
    case 384:
        eckey = EC_KEY_new_by_curve_name(CURVE384);
        break;
    case 521:
        eckey = EC_KEY_new_by_curve_name(CURVE521);
        break;
    default:
        eckey = NULL;
    }
    if (eckey == NULL) goto err;

    group_order = BN_new();
    if (group_order == NULL) goto err;

    ret->eckey = eckey;
    ret->group_order = group_order;
    ret->sk = NULL;
    ret->PK = NULL;
    ret->bytelen_go = 0;
    return ret;
err:
    ECSNOR_keypair_free(ret);
    return NULL;
}


int ECSNOR_keypair_gen(int sec, void *obj)
{
    int ret = 0;

    ECSNOR_KeyPair *keypair = (ECSNOR_KeyPair*)obj;
    ret = EC_KEY_generate_key(keypair->eckey);
    if (ret == 0)
    {
        ret = -1;
        goto final;
    }

    const EC_GROUP *grp = EC_KEY_get0_group(keypair->eckey);
    keypair->group = grp;
    EC_GROUP_get_order(grp, keypair->group_order, bnctx);
    keypair->sk = EC_KEY_get0_private_key(keypair->eckey);
    keypair->PK = EC_KEY_get0_public_key(keypair->eckey);
    keypair->bytelen_go = BN_num_bytes(keypair->group_order);
    keypair->bytelen_point = EC_POINT_point2oct(
        grp, keypair->PK, POINT_CONVERSION_COMPRESSED, NULL, 0, bnctx);
    ret = 0;

    final:
    return ret;
}


const char *ECSNOR_get_name()
{
    return "ECSNOR";
}


void ECSNOR_signature_free(void* obj)
{
    if (obj == NULL) return;
    ECSNOR_Sig *sig = (ECSNOR_Sig*)obj;
    BN_free(sig->f);
    BN_free(sig->z);
    free(sig);
}


void *ECSNOR_signature_new(void *keyobj)
{
    ECSNOR_Sig *sig = malloc(sizeof(ECSNOR_Sig));
    if (sig == NULL) return NULL;

    void *flag = NULL;
    flag = sig->f = BN_new();if (flag == NULL) goto err;
    flag = sig->z = BN_new();if (flag == NULL) goto err;
    return sig;
err:
    ECSNOR_signature_free(sig);
    return NULL;
}


int ECSNOR_get_sig_len(void *obj)
{
    ECSNOR_Sig *sig = (ECSNOR_Sig*)obj;
    return -1;//TODO
}


int ECSNOR_sig_encode(void *obj, unsigned char *buf)
{
    ECSNOR_Sig *sig = (ECSNOR_Sig*)obj;
    return -1;//TODO
}















void ECSNOR_d0_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECSNOR_SignSessD0 *sess = (ECSNOR_SignSessD0*)obj;
    BN_free(sess->r);
    EC_POINT_free(sess->A);
    BN_free(sess->fx);
    free(sess->f_bytes);
    free(sess->A_bytes_m);
    free(sess);
}


void *ECSNOR_d0_signsess_new(void *keyobj)
{
    ECSNOR_KeyPair *keypair = (ECSNOR_KeyPair*)keyobj;

    ECSNOR_SignSessD0 *sess = malloc(sizeof(ECSNOR_SignSessD0));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECSNOR_SignSessD0));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A_bytes_m = malloc(keypair->bytelen_point+1024);if (flag == NULL) goto err;
    flag = sess->fx = BN_new();if (flag == NULL) goto err;
    flag = sess->f_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    return sess;
err:
    ECSNOR_d0_signsess_free(sess);
    return NULL;
}


void ECSNOR_d0_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECSNOR_VrfySessD0 *sess = (ECSNOR_VrfySessD0*)obj;
    free(sess->A_bytes_m);
    free(sess->f0_bytes);
    BN_free(sess->neg_f);
    BN_free(sess->f0);
    EC_POINT_free(sess->A);
    free(sess);
}


void *ECSNOR_d0_vrfysess_new(void *keyobj)
{
    ECSNOR_KeyPair *keypair = (ECSNOR_KeyPair*)keyobj;
    ECSNOR_VrfySessD0 *sess = malloc(sizeof(ECSNOR_VrfySessD0));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECSNOR_VrfySessD0));

    void *flag = NULL;
    flag = sess->A_bytes_m = malloc(keypair->bytelen_point+1024);if (flag == NULL) goto err;
    flag = sess->f0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->neg_f = BN_new();if (flag == NULL) goto err;
    flag = sess->f0 = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    return sess;
err:
    ECSNOR_d0_vrfysess_free(sess);
    return NULL;
}


int ECSNOR_d0_sign(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECSNOR_KeyPair *keys = (ECSNOR_KeyPair*)keyobj;
    ECSNOR_SignSessD0 *sess = (ECSNOR_SignSessD0*)sessobj;
    ECSNOR_Sig *sig = (ECSNOR_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes_m, ret, bnctx);

    /* Get A||m */
    memcpy(sess->A_bytes_m + keys->bytelen_point, msg, msglen);

    /* Compute f_bytes = H(A||m) */
    PRG(sess->A_bytes_m, keys->bytelen_point+msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert f_bytes to f */
    BN_bin2bn(sess->f_bytes, keys->bytelen_go, sig->f);

    /* Compute fx */
    BN_mod_mul(sess->fx, sig->f, keys->sk, keys->group_order, bnctx);

    /* Compute z=r+fx */
    ret = BN_mod_add(sig->z, sess->r, sess->fx, keys->group_order, bnctx);
    assert(ret == 1);

    return 0;
}


int ECSNOR_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECSNOR_KeyPair *keys = (ECSNOR_KeyPair*)keyobj;
    ECSNOR_VrfySessD0 *sess = (ECSNOR_VrfySessD0*)sessobj;
    ECSNOR_Sig *sig = (ECSNOR_Sig*)sigobj;
    int ret;

    /* Get -f */
    BN_mod_sub(sess->neg_f, keys->group_order, sig->f, keys->group_order, bnctx);

    /* Compute A = zP-fX  */
    ret = EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->neg_f, bnctx);
    
    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes_m, ret, bnctx);

    /* Get A||m */
    memcpy(sess->A_bytes_m + keys->bytelen_point, msg, msglen);

    /* Compute f0_bytes = H(A||m) */
    PRG(sess->A_bytes_m, keys->bytelen_point + msglen, sess->f0_bytes, keys->bytelen_go);

    /* Convert f0_bytes to f0 */
    BN_bin2bn(sess->f0_bytes, keys->bytelen_go, sess->f0);

    /* Check f=f0? */
    ret = BN_cmp(sig->f, sess->f0);
    if (ret != 0) return -1;

    return 0;
}










SchemeMethods ECSNOR_Methods =
{
    .mthd_keypair_new = ECSNOR_keypair_new,
    .mthd_keypair_free = ECSNOR_keypair_free,
    .mthd_keypair_gen = ECSNOR_keypair_gen,
    .mthd_get_name = ECSNOR_get_name,
    .mthd_signature_new = ECSNOR_signature_new,
    .mthd_signature_free = ECSNOR_signature_free,
    .mthd_get_sig_len = ECSNOR_get_sig_len,
    .mthd_sig_encode = ECSNOR_sig_encode,

    .mthd_signsess_d3_new = NULL,
    .mthd_signsess_d3_free = NULL,
    .mthd_vrfysess_d3_new = NULL,
    .mthd_vrfysess_d3_free = NULL,
    .mthd_d3_sign_offline = NULL,
    .mthd_d3_sign_online = NULL,
    .mthd_d3_vrfy_offline = NULL,
    .mthd_d3_vrfy_online = NULL,

    .mthd_signsess_d3b_new = NULL,
    .mthd_signsess_d3b_free = NULL,
    .mthd_vrfysess_d3b_new = NULL,
    .mthd_vrfysess_d3b_free = NULL,
    .mthd_d3b_sign_offline = NULL,
    .mthd_d3b_sign_online = NULL,
    .mthd_d3b_vrfy_offline = NULL,
    .mthd_d3b_vrfy_online = NULL,

    .mthd_signsess_d2_new = NULL,
    .mthd_signsess_d2_free = NULL,
    .mthd_vrfysess_d2_new = NULL,
    .mthd_vrfysess_d2_free = NULL,
    .mthd_d2_sign_offline = NULL,
    .mthd_d2_sign_online = NULL,
    .mthd_d2_vrfy_offline = NULL,
    .mthd_d2_vrfy_online = NULL,

    .mthd_signsess_d2b_new = NULL,
    .mthd_signsess_d2b_free = NULL,
    .mthd_vrfysess_d2b_new = NULL,
    .mthd_vrfysess_d2b_free = NULL,
    .mthd_d2b_sign_offline = NULL,
    .mthd_d2b_sign_online = NULL,
    .mthd_d2b_vrfy_offline = NULL,
    .mthd_d2b_vrfy_online = NULL,

    .mthd_signsess_d1_new = NULL,
    .mthd_signsess_d1_free = NULL,
    .mthd_vrfysess_d1_new = NULL,
    .mthd_vrfysess_d1_free = NULL,
    .mthd_d1_sign_offline = NULL,
    .mthd_d1_sign_online = NULL,
    .mthd_d1_vrfy_offline = NULL,
    .mthd_d1_vrfy_online = NULL,

    .mthd_signsess_d0_new = ECSNOR_d0_signsess_new,
    .mthd_signsess_d0_free = ECSNOR_d0_signsess_free,
    .mthd_vrfysess_d0_new = ECSNOR_d0_vrfysess_new,
    .mthd_vrfysess_d0_free = ECSNOR_d0_vrfysess_free,
    .mthd_d0_sign = ECSNOR_d0_sign,
    .mthd_d0_vrfy = ECSNOR_d0_vrfy,
};


