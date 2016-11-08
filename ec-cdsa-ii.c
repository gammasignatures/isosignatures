
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


typedef struct ECCDSA2_KeyPair ECCDSA2_KeyPair;
struct ECCDSA2_KeyPair
{
	EC_KEY*         eckey;
	const EC_GROUP* group;
	BIGNUM*         group_order;
	const BIGNUM*   sk;              // private key
	const EC_POINT* PK;              // public key
	int             bytelen_go;
	int             bytelen_point;
};


typedef struct ECCDSA2_Sig ECCDSA2_Sig;
struct ECCDSA2_Sig
{
    unsigned char *d_bytes;
	BIGNUM*	z;
};


typedef struct ECCDSA2_SignSessD3 ECCDSA2_SignSessD3;
struct ECCDSA2_SignSessD3
{
	BIGNUM*         r;
	EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA2_VrfySessD3 ECCDSA2_VrfySessD3;
struct ECCDSA2_VrfySessD3
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       edX;
	EC_POINT*       zP;
	EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  d0_bytes;
};


typedef struct ECCDSA2_SignSessD2 ECCDSA2_SignSessD2;
struct ECCDSA2_SignSessD2
{
    BIGNUM*         r;
    EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  e_bytes;
    unsigned char*  ed_bytes;
    BIGNUM*         ed;
    BIGNUM*			xed;
};


typedef struct ECCDSA2_VrfySessD2 ECCDSA2_VrfySessD2;
struct ECCDSA2_VrfySessD2
{
    unsigned char*  e_bytes;
    unsigned char*  ed_bytes;
    BIGNUM*         ed;
    EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  d0_bytes;
};


typedef struct ECCDSA2_SignSessD1 ECCDSA2_SignSessD1;
struct ECCDSA2_SignSessD1
{
    BIGNUM*         r;
    EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  e_bytes;
    unsigned char*  ed_bytes;
    BIGNUM*         ed;
    BIGNUM*			xed;
};


typedef struct ECCDSA2_VrfySessD1 ECCDSA2_VrfySessD1;
struct ECCDSA2_VrfySessD1
{
    unsigned char*  e_bytes;
    unsigned char*  ed_bytes;
    BIGNUM*         ed;
    EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  d0_bytes;
};



typedef struct ECCDSA2_SignSessD0 ECCDSA2_SignSessD0;
struct ECCDSA2_SignSessD0
{
    BIGNUM*         r;
    EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  e_bytes;
    unsigned char*  ed_bytes;
    BIGNUM*         ed;
    BIGNUM*			xed;
};


typedef struct ECCDSA2_VrfySessD0 ECCDSA2_VrfySessD0;
struct ECCDSA2_VrfySessD0
{
    unsigned char*  e_bytes;
    unsigned char*  ed_bytes;
    BIGNUM*         ed;
    EC_POINT*       A;
    BIGNUM*         d;
    unsigned char*  d0_bytes;
};


void *ECCDSA2_keypair_new(int sec);
void ECCDSA2_keypair_free(void *obj);
int ECCDSA2_keypair_gen(int sec, void *obj);
const char *ECCDSA2_get_name();
void *ECCDSA2_signature_new(void *keyobj);
void ECCDSA2_signature_free(void* obj);
int ECCDSA2_get_sig_len(void *obj);
int ECCDSA2_sig_encode(void *obj, unsigned char *buf);

void *ECCDSA2_d3_signsess_new(void *keyobj);
void ECCDSA2_d3_signsess_free(void* obj);
void *ECCDSA2_d3_vrfysess_new(void *keyobj);
void ECCDSA2_d3_vrfysess_free(void* obj);
int ECCDSA2_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECCDSA2_d3_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECCDSA2_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECCDSA2_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj);

void *ECCDSA2_d2_signsess_new(void *keyobj);
void ECCDSA2_d2_signsess_free(void* obj);
void *ECCDSA2_d2_vrfysess_new(void *keyobj);
void ECCDSA2_d2_vrfysess_free(void* obj);
int ECCDSA2_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECCDSA2_d2_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECCDSA2_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj);
int ECCDSA2_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECCDSA2_d1_signsess_new(void *keyobj);
void ECCDSA2_d1_signsess_free(void* obj);
void *ECCDSA2_d1_vrfysess_new(void *keyobj);
void ECCDSA2_d1_vrfysess_free(void* obj);
int ECCDSA2_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECCDSA2_d1_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECCDSA2_d1_vrfy_offline(void *keyobj, void *sessobj);
int ECCDSA2_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECCDSA2_d0_signsess_new(void *keyobj);
void ECCDSA2_d0_signsess_free(void* obj);
void *ECCDSA2_d0_vrfysess_new(void *keyobj);
void ECCDSA2_d0_vrfysess_free(void* obj);
int ECCDSA2_d0_sign(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECCDSA2_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);


SchemeMethods ECCDSA2_Methods =
{
	.mthd_keypair_new = ECCDSA2_keypair_new,
	.mthd_keypair_free = ECCDSA2_keypair_free,
	.mthd_keypair_gen = ECCDSA2_keypair_gen,
	.mthd_get_name = ECCDSA2_get_name,
	.mthd_signature_new = ECCDSA2_signature_new,
	.mthd_signature_free = ECCDSA2_signature_free,
	.mthd_get_sig_len = ECCDSA2_get_sig_len,
	.mthd_sig_encode = ECCDSA2_sig_encode,

    .mthd_signsess_d3_new = ECCDSA2_d3_signsess_new,
    .mthd_signsess_d3_free = ECCDSA2_d3_signsess_free,
    .mthd_vrfysess_d3_new = ECCDSA2_d3_vrfysess_new,
    .mthd_vrfysess_d3_free = ECCDSA2_d3_vrfysess_free,
    .mthd_d3_sign_offline = ECCDSA2_d3_sign_offline,
    .mthd_d3_sign_online = ECCDSA2_d3_sign_online,
    .mthd_d3_vrfy_offline = ECCDSA2_d3_vrfy_offline,
    .mthd_d3_vrfy_online = ECCDSA2_d3_vrfy_online,

    .mthd_signsess_d3b_new = NULL,
    .mthd_signsess_d3b_free = NULL,
    .mthd_vrfysess_d3b_new = NULL,
    .mthd_vrfysess_d3b_free = NULL,
    .mthd_d3b_sign_offline = NULL,
    .mthd_d3b_sign_online = NULL,
    .mthd_d3b_vrfy_offline = NULL,
    .mthd_d3b_vrfy_online = NULL,

    .mthd_signsess_d2_new = ECCDSA2_d2_signsess_new,
    .mthd_signsess_d2_free = ECCDSA2_d2_signsess_free,
    .mthd_vrfysess_d2_new = ECCDSA2_d2_vrfysess_new,
    .mthd_vrfysess_d2_free = ECCDSA2_d2_vrfysess_free,
    .mthd_d2_sign_offline = ECCDSA2_d2_sign_offline,
    .mthd_d2_sign_online = ECCDSA2_d2_sign_online,
    .mthd_d2_vrfy_offline = ECCDSA2_d2_vrfy_offline,
    .mthd_d2_vrfy_online = ECCDSA2_d2_vrfy_online,

    .mthd_signsess_d2b_new = NULL,
    .mthd_signsess_d2b_free = NULL,
    .mthd_vrfysess_d2b_new = NULL,
    .mthd_vrfysess_d2b_free = NULL,
    .mthd_d2b_sign_offline = NULL,
    .mthd_d2b_sign_online = NULL,
    .mthd_d2b_vrfy_offline = NULL,
    .mthd_d2b_vrfy_online = NULL,

    .mthd_signsess_d1_new = ECCDSA2_d1_signsess_new,
	.mthd_signsess_d1_free = ECCDSA2_d1_signsess_free,
	.mthd_vrfysess_d1_new = ECCDSA2_d1_vrfysess_new,
	.mthd_vrfysess_d1_free = ECCDSA2_d1_vrfysess_free,
	.mthd_d1_sign_offline = ECCDSA2_d1_sign_offline,
	.mthd_d1_sign_online = ECCDSA2_d1_sign_online,
	.mthd_d1_vrfy_offline = ECCDSA2_d1_vrfy_offline,
	.mthd_d1_vrfy_online = ECCDSA2_d1_vrfy_online,

	.mthd_signsess_d0_new = ECCDSA2_d0_signsess_new,
	.mthd_signsess_d0_free = ECCDSA2_d0_signsess_free,
	.mthd_vrfysess_d0_new = ECCDSA2_d0_vrfysess_new,
	.mthd_vrfysess_d0_free = ECCDSA2_d0_vrfysess_free,
	.mthd_d0_sign = ECCDSA2_d0_sign,
	.mthd_d0_vrfy = ECCDSA2_d0_vrfy,
};


void *ECCDSA2_keypair_new(int sec)
{
	BIGNUM *w = NULL;
	BIGNUM *group_order = NULL;
	EC_POINT *h = NULL;
	EC_KEY *eckey = NULL;

	ECCDSA2_KeyPair *ret = NULL;

	ret = malloc(sizeof(ECCDSA2_KeyPair));
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


void ECCDSA2_keypair_free(void *obj)
{
	ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)obj;
	EC_KEY_free(keypair->eckey);
	BN_free(keypair->group_order);
	free(keypair);
}


int ECCDSA2_keypair_gen(int sec, void *obj)
{
	int ret = 0;

	ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)obj;
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


const char *ECCDSA2_get_name()
{
	return "EC-KCDSA";
}


void *ECCDSA2_signature_new(void *keyobj)
{
	ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair *)keyobj;
	ECCDSA2_Sig *sig = malloc(sizeof(ECCDSA2_Sig));
	if (sig == NULL) return NULL;

	void *flag = NULL;
    flag = sig->z = BN_new();if (flag == NULL) goto err;
    flag = sig->d_bytes = malloc(keys->bytelen_go);if (flag == NULL) goto err;
	return sig;
err:
	ECCDSA2_signature_free(sig);
	return NULL;
}


void ECCDSA2_signature_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)obj;
    BN_free(sig->z);
    free(sig->d_bytes);
	free(sig);
}


int ECCDSA2_get_sig_len(void *obj)
{
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)obj;
	return -1;//TODO
}


int ECCDSA2_sig_encode(void *obj, unsigned char *buf)
{
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)obj;
	return -1;//TODO
}























void *ECCDSA2_d3_signsess_new(void *keyobj)
{
	ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;

	ECCDSA2_SignSessD3 *sess = malloc(sizeof(ECCDSA2_SignSessD3));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA2_SignSessD3));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->d = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA2_d3_signsess_free(sess);
	return NULL;
}


void ECCDSA2_d3_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA2_SignSessD3 *sess = (ECCDSA2_SignSessD3*)obj;
	BN_free(sess->r);
	BN_free(sess->d);
	EC_POINT_free(sess->A);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA2_d3_vrfysess_new(void *keyobj)
{
	ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;
	ECCDSA2_VrfySessD3 *sess = malloc(sizeof(ECCDSA2_VrfySessD3));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA2_VrfySessD3));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->edX = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->zP = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA2_d3_vrfysess_free(sess);
	return NULL;
}


void ECCDSA2_d3_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA2_VrfySessD3 *sess = (ECCDSA2_VrfySessD3*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->edX);
	EC_POINT_free(sess->zP);
	EC_POINT_free(sess->A);
    BN_free(sess->d);
    free(sess->d0_bytes);
	free(sess);
}


int ECCDSA2_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
	ECCDSA2_SignSessD3 *sess = (ECCDSA2_SignSessD3*)sessobj;
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
	int ret;

	/* Pick r */
	ret = BN_rand_range(sess->r, keys->group_order);
	assert(ret == 1);

	/* Compute A = rP */
	ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
	assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sig->d_bytes, keys->bytelen_go);

	return 0;
}


int ECCDSA2_d3_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
	ECCDSA2_SignSessD3 *sess = (ECCDSA2_SignSessD3*)sessobj;
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* Compute x(e xor d)*/
    ret = BN_mod_mul(sess->xed, keys->sk, sess->ed, keys->group_order, bnctx);
    assert(ret == 1);

	/* Compute z = r - x(d xor e) */
	BN_mod_sub(sig->z, sess->r, sess->xed, keys->group_order, bnctx);

	return 0;
}


int ECCDSA2_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
	ECCDSA2_VrfySessD3 *sess = (ECCDSA2_VrfySessD3*)sessobj;
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* Compute (e xor d)X */
	EC_POINT_mul(keys->group, sess->edX, NULL, keys->PK, sess->ed, bnctx);

	return 0;
}


int ECCDSA2_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
	ECCDSA2_VrfySessD3 *sess = (ECCDSA2_VrfySessD3*)sessobj;
	ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
	int ret;

	/* Compute zP   */
	ret = EC_POINT_mul(keys->group, sess->zP, sig->z, NULL, NULL, bnctx);

	/* A = (e xor d)X + zP */
	EC_POINT_add(keys->group, sess->A, sess->zP, sess->edX, bnctx);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}
































void *ECCDSA2_d2_signsess_new(void *keyobj)
{
    ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;

    ECCDSA2_SignSessD2 *sess = malloc(sizeof(ECCDSA2_SignSessD2));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECCDSA2_SignSessD2));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed = BN_new();if (flag == NULL) goto err;
    flag = sess->xed = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECCDSA2_d2_signsess_free(sess);
    return NULL;
}


void ECCDSA2_d2_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECCDSA2_SignSessD2 *sess = (ECCDSA2_SignSessD2*)obj;
    BN_free(sess->r);
    BN_free(sess->d);
    EC_POINT_free(sess->A);
    free(sess->e_bytes);
    free(sess->ed_bytes);
    BN_free(sess->ed);
    BN_free(sess->xed);
    free(sess);
}


void *ECCDSA2_d2_vrfysess_new(void *keyobj)
{
    ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD2 *sess = malloc(sizeof(ECCDSA2_VrfySessD2));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECCDSA2_VrfySessD2));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    return sess;
err:
    ECCDSA2_d2_vrfysess_free(sess);
    return NULL;
}


void ECCDSA2_d2_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECCDSA2_VrfySessD2 *sess = (ECCDSA2_VrfySessD2*)obj;
    free(sess->e_bytes);
    free(sess->ed_bytes);
    BN_free(sess->ed);
    EC_POINT_free(sess->A);
    BN_free(sess->d);
    free(sess->d0_bytes);
    free(sess);
}


int ECCDSA2_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_SignSessD2 *sess = (ECCDSA2_SignSessD2*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sig->d_bytes, keys->bytelen_go);

    return 0;
}


int ECCDSA2_d2_sign_online(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_SignSessD2 *sess = (ECCDSA2_SignSessD2*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Compute e_xor_d_bytes */
    BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

    /* Convert e_xor_d_bytes to e_xor_d */
    BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* Compute x(e xor d)*/
    ret = BN_mod_mul(sess->xed, keys->sk, sess->ed, keys->group_order, bnctx);
    assert(ret == 1);

    /* Compute z = r - x(d xor e) */
    BN_mod_sub(sig->z, sess->r, sess->xed, keys->group_order, bnctx);

    return 0;
}


int ECCDSA2_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj)
{
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD2 *sess = (ECCDSA2_VrfySessD2*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    return 0;
}


int ECCDSA2_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD2 *sess = (ECCDSA2_VrfySessD2*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Compute e_xor_d_bytes */
    BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

    /* Convert e_xor_d_bytes to e_xor_d */
    BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* A = (e xor d)X + zP */
    ret = EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->ed, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sess->d0_bytes, keys->bytelen_go);

    /* Check d=d0? */
    ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
    if (ret != 0) return -1;

    return 0;
}



































void *ECCDSA2_d1_signsess_new(void *keyobj)
{
    ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;

    ECCDSA2_SignSessD1 *sess = malloc(sizeof(ECCDSA2_SignSessD1));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECCDSA2_SignSessD1));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed = BN_new();if (flag == NULL) goto err;
    flag = sess->xed = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECCDSA2_d1_signsess_free(sess);
    return NULL;
}


void ECCDSA2_d1_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECCDSA2_SignSessD1 *sess = (ECCDSA2_SignSessD1*)obj;
    BN_free(sess->r);
    BN_free(sess->d);
    EC_POINT_free(sess->A);
    free(sess->e_bytes);
    free(sess->ed_bytes);
    BN_free(sess->ed);
    BN_free(sess->xed);
    free(sess);
}


void *ECCDSA2_d1_vrfysess_new(void *keyobj)
{
    ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD1 *sess = malloc(sizeof(ECCDSA2_VrfySessD1));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECCDSA2_VrfySessD1));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    return sess;
err:
    ECCDSA2_d1_vrfysess_free(sess);
    return NULL;
}


void ECCDSA2_d1_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECCDSA2_VrfySessD1 *sess = (ECCDSA2_VrfySessD1*)obj;
    free(sess->e_bytes);
    free(sess->ed_bytes);
    BN_free(sess->ed);
    EC_POINT_free(sess->A);
    BN_free(sess->d);
    free(sess->d0_bytes);
    free(sess);
}


int ECCDSA2_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
    /* Rename objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_SignSessD1 *sess = (ECCDSA2_SignSessD1*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sig->d_bytes, keys->bytelen_go);

    return 0;
}


int ECCDSA2_d1_sign_online(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_SignSessD1 *sess = (ECCDSA2_SignSessD1*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Compute e_xor_d_bytes */
    BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

    /* Convert e_xor_d_bytes to e_xor_d */
    BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* Compute x(e xor d)*/
    ret = BN_mod_mul(sess->xed, keys->sk, sess->ed, keys->group_order, bnctx);
    assert(ret == 1);

    /* Compute z = r - x(d xor e) */
    BN_mod_sub(sig->z, sess->r, sess->xed, keys->group_order, bnctx);

    return 0;
}


int ECCDSA2_d1_vrfy_offline(void *keyobj, void *sessobj)
{
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD1 *sess = (ECCDSA2_VrfySessD1*)sessobj;
    int ret;

    return 0;
}


int ECCDSA2_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD1 *sess = (ECCDSA2_VrfySessD1*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Compute e_xor_d_bytes */
    BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

    /* Convert e_xor_d_bytes to e_xor_d */
    BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* A = (e xor d)X + zP */
    ret = EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->ed, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sess->d0_bytes, keys->bytelen_go);

    /* Check d=d0? */
    ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
    if (ret != 0) return -1;

    return 0;
}





























void *ECCDSA2_d0_signsess_new(void *keyobj)
{
    ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;

    ECCDSA2_SignSessD0 *sess = malloc(sizeof(ECCDSA2_SignSessD0));
    if (sess == NULL) return NULL;

    memset(sess, 0, sizeof(ECCDSA2_SignSessD0));

    void *flag = NULL;
    flag = sess->r = BN_new();if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed = BN_new();if (flag == NULL) goto err;
    flag = sess->xed = BN_new();if (flag == NULL) goto err;
    return sess;
err:
    ECCDSA2_d0_signsess_free(sess);
    return NULL;
}


void ECCDSA2_d0_signsess_free(void* obj)
{
    if (obj == NULL) return;
    ECCDSA2_SignSessD0 *sess = (ECCDSA2_SignSessD0*)obj;
    BN_free(sess->r);
    BN_free(sess->d);
    EC_POINT_free(sess->A);
    free(sess->e_bytes);
    free(sess->ed_bytes);
    BN_free(sess->ed);
    BN_free(sess->xed);
    free(sess);
}


void *ECCDSA2_d0_vrfysess_new(void *keyobj)
{
    ECCDSA2_KeyPair *keypair = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD0 *sess = malloc(sizeof(ECCDSA2_VrfySessD0));
    if (sess == NULL) return NULL;
    memset(sess, 0, sizeof(ECCDSA2_VrfySessD0));

    void *flag = NULL;
    flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    flag = sess->ed = BN_new();if (flag == NULL) goto err;
    flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
    flag = sess->d = BN_new();if (flag == NULL) goto err;
    flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
    return sess;
err:
    ECCDSA2_d0_vrfysess_free(sess);
    return NULL;
}


void ECCDSA2_d0_vrfysess_free(void* obj)
{
    if (obj == NULL) return;
    ECCDSA2_VrfySessD0 *sess = (ECCDSA2_VrfySessD0*)obj;
    free(sess->e_bytes);
    free(sess->ed_bytes);
    BN_free(sess->ed);
    EC_POINT_free(sess->A);
    BN_free(sess->d);
    free(sess->d0_bytes);
    free(sess);
}


int ECCDSA2_d0_sign(void *keyobj, void *sessobj, void *sigobj,
    const unsigned char *msg, int msglen)
{
    /* Cast objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_SignSessD0 *sess = (ECCDSA2_SignSessD0*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Pick r */
    ret = BN_rand_range(sess->r, keys->group_order);
    assert(ret == 1);

    /* Compute A = rP */
    ret = EC_POINT_mul(keys->group, sess->A, sess->r, NULL, NULL, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sig->d_bytes, keys->bytelen_go);

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Compute e_xor_d_bytes */
    BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

    /* Convert e_xor_d_bytes to e_xor_d */
    BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* Compute x(e xor d)*/
    ret = BN_mod_mul(sess->xed, keys->sk, sess->ed, keys->group_order, bnctx);
    assert(ret == 1);

    /* Compute z = r - x(d xor e) */
    BN_mod_sub(sig->z, sess->r, sess->xed, keys->group_order, bnctx);

    return 0;
}


int ECCDSA2_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
    /* Rename objects. */
    ECCDSA2_KeyPair *keys = (ECCDSA2_KeyPair*)keyobj;
    ECCDSA2_VrfySessD0 *sess = (ECCDSA2_VrfySessD0*)sessobj;
    ECCDSA2_Sig *sig = (ECCDSA2_Sig*)sigobj;
    int ret;

    /* Compute e_bytes = H(m) */
    PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

    /* Compute e_xor_d_bytes */
    BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

    /* Convert e_xor_d_bytes to e_xor_d */
    BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

    /* A = (e xor d)X + zP */
    ret = EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->ed, bnctx);
    assert(ret == 1);

    /* Get d = A.x */
    ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d, NULL, bnctx);
    assert(ret == 1);

    /* Get d_bytes from d */
    BN2LenBin(sess->d, sess->d0_bytes, keys->bytelen_go);

    /* Check d=d0? */
    ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
    if (ret != 0) return -1;

    return 0;
}
