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




void *ECRDSA_keypair_new(int sec);
void ECRDSA_keypair_free(void *obj);
int ECRDSA_keypair_gen(int sec, void *obj);
const char *ECRDSA_get_name();
void *ECRDSA_signature_new(void *keyobj);
void ECRDSA_signature_free(void* obj);
int ECRDSA_get_sig_len(void *obj);
int ECRDSA_sig_encode(void *obj, unsigned char *buf);

void *ECRDSA_d3_signsess_new(void *keyobj);
void ECRDSA_d3_signsess_free(void* obj);
void *ECRDSA_d3_vrfysess_new(void *keyobj);
void ECRDSA_d3_vrfysess_free(void* obj);
int ECRDSA_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECRDSA_d3_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECRDSA_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECRDSA_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj);

void *ECRDSA_d2_signsess_new(void *keyobj);
void ECRDSA_d2_signsess_free(void* obj);
void *ECRDSA_d2_vrfysess_new(void *keyobj);
void ECRDSA_d2_vrfysess_free(void* obj);
int ECRDSA_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECRDSA_d2_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECRDSA_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj);
int ECRDSA_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECRDSA_d1_signsess_new(void *keyobj);
void ECRDSA_d1_signsess_free(void* obj);
void *ECRDSA_d1_vrfysess_new(void *keyobj);
void ECRDSA_d1_vrfysess_free(void* obj);
int ECRDSA_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECRDSA_d1_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECRDSA_d1_vrfy_offline(void *keyobj, void *sessobj);
int ECRDSA_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECRDSA_d0_signsess_new(void *keyobj);
void ECRDSA_d0_signsess_free(void* obj);
void *ECRDSA_d0_vrfysess_new(void *keyobj);
void ECRDSA_d0_vrfysess_free(void* obj);
int ECRDSA_d0_sign(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECRDSA_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);



typedef struct ECRDSA_KeyPair ECRDSA_KeyPair;
struct ECRDSA_KeyPair
{
    EC_KEY*         eckey;
    const EC_GROUP* group;
    BIGNUM*         group_order;
    const BIGNUM*   sk;              // private key
    const EC_POINT* PK;              // public key
    int             bytelen_go;
    int             bytelen_point;
};


typedef struct ECRDSA_Sig ECRDSA_Sig;
struct ECRDSA_Sig
{
    BIGNUM*	d;
    BIGNUM*	z;
};



void *ECRDSA_keypair_new(int sec)
{
    BIGNUM *w = NULL;
    BIGNUM *group_order = NULL;
    EC_POINT *h = NULL;
    EC_KEY *eckey = NULL;

    ECRDSA_KeyPair *ret = NULL;

    ret = malloc(sizeof(ECRDSA_KeyPair));
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
    free(ret);
    EC_KEY_free(eckey);
    BN_free(w);
    BN_free(group_order);
    EC_POINT_free(h);
    return NULL;
}


void ECRDSA_keypair_free(void *obj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)obj;
    EC_KEY_free(keypair->eckey);
    BN_free(keypair->group_order);
    free(keypair);
}


int ECRDSA_keypair_gen(int sec, void *obj)
{
    int ret = 0;

    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)obj;
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


const char *ECRDSA_get_name()
{
    return "ECRDSA";
}


void *ECRDSA_signature_new(void *keyobj)
{
    ECRDSA_Sig *sig = malloc(sizeof(ECRDSA_Sig));
    if (sig == NULL) return NULL;

    void *flag = NULL;
    flag = sig->d = BN_new();if (flag == NULL) goto err;
    flag = sig->z = BN_new();if (flag == NULL) goto err;
    return sig;
err:
    ECRDSA_signature_free(sig);
    return NULL;
}


void ECRDSA_signature_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)obj;
    BN_free(sig->d);
    BN_free(sig->z);
    free(sig);
}



int ECRDSA_get_sig_len(void *obj)
{
    ECRDSA_Sig *sig = (ECRDSA_Sig*)obj;
    return -1;//TODO
}


int ECRDSA_sig_encode(void *obj, unsigned char *buf)
{
    ECRDSA_Sig *sig = (ECRDSA_Sig*)obj;
    return -1;//TODO
}













typedef struct ECRDSA_SignSessD3 ECRDSA_SignSessD3;
struct ECRDSA_SignSessD3
{
    BIGNUM*         r;
    BIGNUM*			r_inv;
    EC_POINT*       A;
    BIGNUM*			dx;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			re;
};


typedef struct ECRDSA_VrfySessD3 ECRDSA_VrfySessD3;
struct ECRDSA_VrfySessD3
{
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			e_inv;
    BIGNUM*			nil;
    BIGNUM*			d_e_inv;
    BIGNUM*			neg_d_e_inv;
    EC_POINT*       A0;
    EC_POINT*       A1;
    EC_POINT*       A00;
    EC_POINT*       A;
    BIGNUM*			d0;
};


void *ECRDSA_d3_signsess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;

    ECRDSA_SignSessD3 *sess = malloc(sizeof(ECRDSA_SignSessD3));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECRDSA_SignSessD3));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->dx = BN_new();if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->re = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d3_signsess_free(sess);
    return NULL;
}


void ECRDSA_d3_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_SignSessD3 *sess = (ECRDSA_SignSessD3*)obj;
    BN_free(sess->r);
    BN_free(sess->r_inv);
    EC_POINT_free(sess->A);
    BN_free(sess->dx);
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->re);
    free(sess);
}


void *ECRDSA_d3_vrfysess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD3 *sess = malloc(sizeof(ECRDSA_VrfySessD3));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECRDSA_VrfySessD3));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->nil = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->d_e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->neg_d_e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->A00 = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A0 = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A1 = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d0 = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d3_vrfysess_free(sess);
    return NULL;
}


void ECRDSA_d3_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_VrfySessD3 *sess = (ECRDSA_VrfySessD3*)obj;
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->e_inv);
    BN_free(sess->nil);
    BN_free(sess->d_e_inv);
    BN_free(sess->neg_d_e_inv);
    EC_POINT_free(sess->A0);
    EC_POINT_free(sess->A00);
    EC_POINT_free(sess->A1);
    EC_POINT_free(sess->A);
    BN_free(sess->d0);
    free(sess);
}


int ECRDSA_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD3 *sess = (ECRDSA_SignSessD3*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute r^(-1) */
    BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sig->d, NULL, bnctx);
    assert(ret == 1);

    /* Compute dx */
    BN_mod_mul(sess->dx, sig->d, keys->sk, keys->group_order, bnctx);

    return 0;
}


int ECRDSA_d3_sign_online(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD3 *sess = (ECRDSA_SignSessD3*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute re */
    ret = BN_mod_mul(sess->re, sess->r, sess->e, keys->group_order, bnctx);
    assert(ret == 1);

    /* z = re+dx */
    ret = BN_mod_add(sig->z, sess->re, sess->dx, keys->group_order, bnctx);
    assert(ret == 1);

    return 0;
}


int ECRDSA_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD3 *sess = (ECRDSA_VrfySessD3*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute e^(-1) */
    BN_mod_inverse(sess->e_inv, sess->e, keys->group_order, bnctx);

    /* Compute -de^(-1) */
    BN_mod_mul(sess->d_e_inv, sig->d, sess->e_inv, keys->group_order, bnctx);
    BN_zero(sess->nil);
    BN_mod_sub(sess->neg_d_e_inv, sess->nil, sess->d_e_inv, keys->group_order, bnctx);

    /* Compute A0 = e^(-1) P */
    EC_POINT_mul(keys->group, sess->A0, sess->e_inv, NULL, NULL, bnctx);

    /* Compute A1 = -d*e^(-1) X */
    EC_POINT_mul(keys->group, sess->A1, NULL, keys->PK, sess->neg_d_e_inv, bnctx);

    return 0;
}


int ECRDSA_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD3 *sess = (ECRDSA_VrfySessD3*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute A = z * A0 + A1 */
    ret = EC_POINT_mul(keys->group, sess->A00, NULL, sess->A0, sig->z, bnctx);
    EC_POINT_add(keys->group, sess->A, sess->A00, sess->A1, bnctx);

    /* Let d0 = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

    /* Check d=d0? */
    ret = BN_cmp(sig->d, sess->d0);
    if (ret != 0) return -1;

    return 0;
}
































typedef struct ECRDSA_SignSessD2 ECRDSA_SignSessD2;
struct ECRDSA_SignSessD2
{
    BIGNUM*         r;
    BIGNUM*			r_inv;
    EC_POINT*       A;
    BIGNUM*			dx;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			re;
};


typedef struct ECRDSA_VrfySessD2 ECRDSA_VrfySessD2;
struct ECRDSA_VrfySessD2
{
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			e_inv;
    BIGNUM*			nil;
    BIGNUM*			neg_e_inv;
    BIGNUM*			e_inv_z;
    EC_POINT*       dX;
    EC_POINT*       A;
    BIGNUM*			d0;
};


void *ECRDSA_d2_signsess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;

    ECRDSA_SignSessD2 *sess = malloc(sizeof(ECRDSA_SignSessD2));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECRDSA_SignSessD2));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->dx = BN_new();if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->re = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d2_signsess_free(sess);
    return NULL;
}


void ECRDSA_d2_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_SignSessD2 *sess = (ECRDSA_SignSessD2*)obj;
    BN_free(sess->r);
    BN_free(sess->r_inv);
    EC_POINT_free(sess->A);
    BN_free(sess->dx);
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->re);
    free(sess);
}


void *ECRDSA_d2_vrfysess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD2 *sess = malloc(sizeof(ECRDSA_VrfySessD2));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECRDSA_VrfySessD2));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->nil = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->neg_e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv_z = BN_new();if (flag == NULL) goto err;
    flag = sess->dX = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d0 = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d2_vrfysess_free(sess);
    return NULL;
}


void ECRDSA_d2_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_VrfySessD2 *sess = (ECRDSA_VrfySessD2*)obj;
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->e_inv);
    BN_free(sess->nil);
    BN_free(sess->neg_e_inv);
    BN_free(sess->e_inv_z);
    EC_POINT_free(sess->dX);
    EC_POINT_free(sess->A);
    BN_free(sess->d0);
    free(sess);
}


int ECRDSA_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD2 *sess = (ECRDSA_SignSessD2*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute r^(-1) */
    BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sig->d, NULL, bnctx);
    assert(ret == 1);

    /* Compute dx */
    BN_mod_mul(sess->dx, sig->d, keys->sk, keys->group_order, bnctx);

    return 0;
}


int ECRDSA_d2_sign_online(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD2 *sess = (ECRDSA_SignSessD2*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute re */
    ret = BN_mod_mul(sess->re, sess->r, sess->e, keys->group_order, bnctx);
    assert(ret == 1);

    /* z = re+dx */
    ret = BN_mod_add(sig->z, sess->re, sess->dx, keys->group_order, bnctx);
    assert(ret == 1);

    return 0;
}


int ECRDSA_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj)
{
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD2 *sess = (ECRDSA_VrfySessD2*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute dX */
    EC_POINT_mul(keys->group, sess->dX, NULL, keys->PK, sig->d, bnctx);
    
    BN_zero(sess->nil);
    return 0;
}


int ECRDSA_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD2 *sess = (ECRDSA_VrfySessD2*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute e^(-1) */
    BN_mod_inverse(sess->e_inv, sess->e, keys->group_order, bnctx);
    
    /* Compute -e^(-1) */
    BN_mod_sub(sess->neg_e_inv, sess->nil, sess->e_inv, keys->group_order,
            bnctx);

    /* Compute e^(-1)z */
    BN_mod_mul(sess->e_inv_z, sess->e_inv, sig->z, keys->group_order, bnctx);

    /* Compute A = e^(-1)z P -e^(-1) (dX) */
    ret = EC_POINT_mul(keys->group, sess->A, sess->e_inv_z, sess->dX, sess->neg_e_inv, bnctx);

    /* Let d0 = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

    /* Check d=d0? */
    ret = BN_cmp(sig->d, sess->d0);
    if (ret != 0) return -1;

    return 0;
}

































typedef struct ECRDSA_SignSessD1 ECRDSA_SignSessD1;
struct ECRDSA_SignSessD1
{
    BIGNUM*         r;
    BIGNUM*			r_inv;
    EC_POINT*       A;
    BIGNUM*			dx;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			re;
};


typedef struct ECRDSA_VrfySessD1 ECRDSA_VrfySessD1;
struct ECRDSA_VrfySessD1
{
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			e_inv;
    BIGNUM*			nil;
    BIGNUM*			neg_e_inv;
    BIGNUM*			e_inv_z;
    BIGNUM*			neg_e_inv_d;
    EC_POINT*       A;
    BIGNUM*			d0;
};


void *ECRDSA_d1_signsess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;

    ECRDSA_SignSessD1 *sess = malloc(sizeof(ECRDSA_SignSessD1));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECRDSA_SignSessD1));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->dx = BN_new();if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->re = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d1_signsess_free(sess);
    return NULL;
}


void ECRDSA_d1_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_SignSessD1 *sess = (ECRDSA_SignSessD1*)obj;
    BN_free(sess->r);
    BN_free(sess->r_inv);
    EC_POINT_free(sess->A);
    BN_free(sess->dx);
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->re);
    free(sess);
}


void *ECRDSA_d1_vrfysess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD1 *sess = malloc(sizeof(ECRDSA_VrfySessD1));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECRDSA_VrfySessD1));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->nil = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->neg_e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv_z = BN_new();if (flag == NULL) goto err;
    flag = sess->neg_e_inv_d = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d0 = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d1_vrfysess_free(sess);
    return NULL;
}


void ECRDSA_d1_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_VrfySessD1 *sess = (ECRDSA_VrfySessD1*)obj;
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->e_inv);
    BN_free(sess->nil);
    BN_free(sess->neg_e_inv);
    BN_free(sess->e_inv_z);
    BN_free(sess->neg_e_inv_d);
    EC_POINT_free(sess->A);
    BN_free(sess->d0);
    free(sess);
}


int ECRDSA_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD1 *sess = (ECRDSA_SignSessD1*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute r^(-1) */
    BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sig->d, NULL, bnctx);
    assert(ret == 1);

    /* Compute dx */
    BN_mod_mul(sess->dx, sig->d, keys->sk, keys->group_order, bnctx);

    return 0;
}


int ECRDSA_d1_sign_online(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD1 *sess = (ECRDSA_SignSessD1*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute re */
    ret = BN_mod_mul(sess->re, sess->r, sess->e, keys->group_order, bnctx);
    assert(ret == 1);

    /* z = re+dx */
    ret = BN_mod_add(sig->z, sess->re, sess->dx, keys->group_order, bnctx);
    assert(ret == 1);

    return 0;
}


int ECRDSA_d1_vrfy_offline(void *keyobj, void *sessobj)
{
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD1 *sess = (ECRDSA_VrfySessD1*)sessobj;

    return 0;
}


int ECRDSA_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD1 *sess = (ECRDSA_VrfySessD1*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute e^(-1) */
    BN_mod_inverse(sess->e_inv, sess->e, keys->group_order, bnctx);
    
    /* Compute -e^(-1) */
    BN_mod_sub(sess->neg_e_inv, sess->nil, sess->e_inv, keys->group_order, bnctx);

    /* Compute e^(-1)z */
    BN_mod_mul(sess->e_inv_z, sess->e_inv, sig->z, keys->group_order, bnctx);

    /* Compute -e^(-1)d */
    BN_mod_mul(sess->neg_e_inv_d, sess->neg_e_inv, sig->d, keys->group_order, bnctx);

    /* Compute A = e^(-1)z P + -e^(-1)d X */
    ret = EC_POINT_mul(keys->group, sess->A, sess->e_inv_z, keys->PK, sess->neg_e_inv_d, bnctx);

    /* Let d0 = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

    /* Check d=d0? */
    ret = BN_cmp(sig->d, sess->d0);
    if (ret != 0) return -1;

    return 0;
}
































typedef struct ECRDSA_SignSessD0 ECRDSA_SignSessD0;
struct ECRDSA_SignSessD0
{
    BIGNUM*         r;
    BIGNUM*			r_inv;
    EC_POINT*       A;
    BIGNUM*			dx;
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			re;
};


typedef struct ECRDSA_VrfySessD0 ECRDSA_VrfySessD0;
struct ECRDSA_VrfySessD0
{
    unsigned char*  e_bytes;
    BIGNUM*         e;
    BIGNUM*			e_inv;
    BIGNUM*			nil;
    BIGNUM*			neg_e_inv;
    BIGNUM*			e_inv_z;
    BIGNUM*			neg_e_inv_d;
    EC_POINT*       A;
    BIGNUM*			d0;
};


void *ECRDSA_d0_signsess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;

    ECRDSA_SignSessD0 *sess = malloc(sizeof(ECRDSA_SignSessD0));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECRDSA_SignSessD0));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->dx = BN_new();if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->re = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d0_signsess_free(sess);
    return NULL;
}


void ECRDSA_d0_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_SignSessD0 *sess = (ECRDSA_SignSessD0*)obj;
    BN_free(sess->r);
    BN_free(sess->r_inv);
    EC_POINT_free(sess->A);
    BN_free(sess->dx);
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->re);
    free(sess);
}


void *ECRDSA_d0_vrfysess_new(void *keyobj)
{
    ECRDSA_KeyPair *keypair = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD0 *sess = malloc(sizeof(ECRDSA_VrfySessD0));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECRDSA_VrfySessD0));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->e = BN_new();if (flag == NULL) goto err;
    flag = sess->nil = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->neg_e_inv = BN_new();if (flag == NULL) goto err;
    flag = sess->e_inv_z = BN_new();if (flag == NULL) goto err;
    flag = sess->neg_e_inv_d = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d0 = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECRDSA_d0_vrfysess_free(sess);
    return NULL;
}


void ECRDSA_d0_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECRDSA_VrfySessD0 *sess = (ECRDSA_VrfySessD0*)obj;
    free(sess->e_bytes);
    BN_free(sess->e);
    BN_free(sess->e_inv);
    BN_free(sess->nil);
    BN_free(sess->neg_e_inv);
    BN_free(sess->e_inv_z);
    BN_free(sess->neg_e_inv_d);
    EC_POINT_free(sess->A);
    BN_free(sess->d0);
    free(sess);
}


int ECRDSA_d0_sign(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_SignSessD0 *sess = (ECRDSA_SignSessD0*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sig->d, NULL, bnctx);
    assert(ret == 1);

    /* Compute dx */
    BN_mod_mul(sess->dx, sig->d, keys->sk, keys->group_order, bnctx);

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute re */
    ret = BN_mod_mul(sess->re, sess->r, sess->e, keys->group_order, bnctx);
    assert(ret == 1);

    /* z = re+dx */
    ret = BN_mod_add(sig->z, sess->re, sess->dx, keys->group_order, bnctx);
    assert(ret == 1);

    return 0;
}


int ECRDSA_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECRDSA_KeyPair *keys = (ECRDSA_KeyPair*)keyobj;
    ECRDSA_VrfySessD0 *sess = (ECRDSA_VrfySessD0*)sessobj;
    ECRDSA_Sig *sig = (ECRDSA_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Convert e_bytes to e */
    BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

    /* Compute e^(-1) */
    BN_mod_inverse(sess->e_inv, sess->e, keys->group_order, bnctx);

    /* Compute -e^(-1) */
    BN_mod_sub(sess->neg_e_inv, sess->nil, sess->e_inv, keys->group_order, bnctx);

    /* Compute e^(-1)z */
    BN_mod_mul(sess->e_inv_z, sess->e_inv, sig->z, keys->group_order, bnctx);

    /* Compute -e^(-1)d */
    BN_mod_mul(sess->neg_e_inv_d, sess->neg_e_inv, sig->d, keys->group_order, bnctx);

    /* Compute A = e^(-1)z P + -e^(-1)d X */
    ret = EC_POINT_mul(keys->group, sess->A, sess->e_inv_z, keys->PK, sess->neg_e_inv_d, bnctx);

    /* Let d0 = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

    /* Check d=d0? */
    ret = BN_cmp(sig->d, sess->d0);
    if (ret != 0) return -1;

    return 0;
}































SchemeMethods ECRDSA_Methods =
{
    .mthd_keypair_new = ECRDSA_keypair_new,
    .mthd_keypair_free = ECRDSA_keypair_free,
    .mthd_keypair_gen = ECRDSA_keypair_gen,
    .mthd_get_name = ECRDSA_get_name,
    .mthd_signature_new = ECRDSA_signature_new,
    .mthd_signature_free = ECRDSA_signature_free,
    .mthd_get_sig_len = ECRDSA_get_sig_len,
    .mthd_sig_encode = ECRDSA_sig_encode,

    .mthd_signsess_d3_new = ECRDSA_d3_signsess_new,
    .mthd_signsess_d3_free = ECRDSA_d3_signsess_free,
    .mthd_vrfysess_d3_new = ECRDSA_d3_vrfysess_new,
    .mthd_vrfysess_d3_free = ECRDSA_d3_vrfysess_free,
    .mthd_d3_sign_offline = ECRDSA_d3_sign_offline,
    .mthd_d3_sign_online = ECRDSA_d3_sign_online,
    .mthd_d3_vrfy_offline = ECRDSA_d3_vrfy_offline,
    .mthd_d3_vrfy_online = ECRDSA_d3_vrfy_online,

    .mthd_signsess_d2_new = ECRDSA_d2_signsess_new,
    .mthd_signsess_d2_free = ECRDSA_d2_signsess_free,
    .mthd_vrfysess_d2_new = ECRDSA_d2_vrfysess_new,
    .mthd_vrfysess_d2_free = ECRDSA_d2_vrfysess_free,
    .mthd_d2_sign_offline = ECRDSA_d2_sign_offline,
    .mthd_d2_sign_online = ECRDSA_d2_sign_online,
    .mthd_d2_vrfy_offline = ECRDSA_d2_vrfy_offline,
    .mthd_d2_vrfy_online = ECRDSA_d2_vrfy_online,

    .mthd_signsess_d1_new = ECRDSA_d1_signsess_new,
    .mthd_signsess_d1_free = ECRDSA_d1_signsess_free,
    .mthd_vrfysess_d1_new = ECRDSA_d1_vrfysess_new,
    .mthd_vrfysess_d1_free = ECRDSA_d1_vrfysess_free,
    .mthd_d1_sign_offline = ECRDSA_d1_sign_offline,
    .mthd_d1_sign_online = ECRDSA_d1_sign_online,
    .mthd_d1_vrfy_offline = ECRDSA_d1_vrfy_offline,
    .mthd_d1_vrfy_online = ECRDSA_d1_vrfy_online,

    .mthd_signsess_d0_new = ECRDSA_d0_signsess_new,
    .mthd_signsess_d0_free = ECRDSA_d0_signsess_free,
    .mthd_vrfysess_d0_new = ECRDSA_d0_vrfysess_new,
    .mthd_vrfysess_d0_free = ECRDSA_d0_vrfysess_free,
    .mthd_d0_sign = ECRDSA_d0_sign,
    .mthd_d0_vrfy = ECRDSA_d0_vrfy,
};

