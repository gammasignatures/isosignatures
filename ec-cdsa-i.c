
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


typedef struct ECCDSA1_KeyPair ECCDSA1_KeyPair;
struct ECCDSA1_KeyPair
{
	EC_KEY*         eckey;
	const EC_GROUP* group;
	BIGNUM*         group_order;
	const BIGNUM*   sk;              // private key
	const EC_POINT* PK;              // public key
	int             bytelen_go;
	int             bytelen_point;
};


typedef struct ECCDSA1_Sig ECCDSA1_Sig;
struct ECCDSA1_Sig
{
	unsigned char *d_bytes;
	BIGNUM*	z;
};


void ECCDSA1_keypair_free(void *obj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)obj;
	EC_KEY_free(keypair->eckey);
	BN_free(keypair->group_order);
	free(keypair);
}


void *ECCDSA1_keypair_new(int sec)
{
	BIGNUM *group_order = NULL;
	EC_KEY *eckey = NULL;

	ECCDSA1_KeyPair *ret = NULL;

	ret = malloc(sizeof(ECCDSA1_KeyPair));
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
	ECCDSA1_keypair_free(ret);
	return NULL;
}


int ECCDSA1_keypair_gen(int sec, void *obj)
{
	int ret = 0;

	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)obj;
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


const char *ECCDSA1_get_name()
{
	return "EC-CDSA-1";
}


void ECCDSA1_signature_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)obj;
	BN_free(sig->z);
	free(sig->d_bytes);
	free(sig);
}


void *ECCDSA1_signature_new(void *keyobj)
{
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair *)keyobj;
	ECCDSA1_Sig *sig = malloc(sizeof(ECCDSA1_Sig));
	if (sig == NULL) return NULL;

	void *flag = NULL;
	flag = sig->z = BN_new();if (flag == NULL) goto err;
	flag = sig->d_bytes = malloc(keys->bytelen_go);if (flag == NULL) goto err;
	return sig;
err:
	ECCDSA1_signature_free(sig);
	return NULL;
}


int ECCDSA1_get_sig_len(void *obj)
{
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)obj;
	return -1;//TODO
}


int ECCDSA1_sig_encode(void *obj, unsigned char *buf)
{
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)obj;
	return -1;//TODO
}























typedef struct ECCDSA1_SignSessD3 ECCDSA1_SignSessD3;
struct ECCDSA1_SignSessD3
{
	BIGNUM*         r;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA1_VrfySessD3 ECCDSA1_VrfySessD3;
struct ECCDSA1_VrfySessD3
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       edX;
	EC_POINT*       zP;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  d0_bytes;
};


void ECCDSA1_d3_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_SignSessD3 *sess = (ECCDSA1_SignSessD3*)obj;
	BN_free(sess->r);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA1_d3_signsess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;

	ECCDSA1_SignSessD3 *sess = malloc(sizeof(ECCDSA1_SignSessD3));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA1_SignSessD3));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d3_signsess_free(sess);
	return NULL;
}


void ECCDSA1_d3_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_VrfySessD3 *sess = (ECCDSA1_VrfySessD3*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->edX);
	EC_POINT_free(sess->zP);
	EC_POINT_free(sess->A);
	free(sess->d0_bytes);
	free(sess);
}


void *ECCDSA1_d3_vrfysess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD3 *sess = malloc(sizeof(ECCDSA1_VrfySessD3));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA1_VrfySessD3));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->edX = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->zP = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d3_vrfysess_free(sess);
	return NULL;
}


int ECCDSA1_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD3 *sess = (ECCDSA1_SignSessD3*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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
		sess->A_bytes, ret, bnctx);

	/* Compute d_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sig->d_bytes, keys->bytelen_go);

	return 0;
}


int ECCDSA1_d3_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD3 *sess = (ECCDSA1_SignSessD3*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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


int ECCDSA1_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD3 *sess = (ECCDSA1_VrfySessD3*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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


int ECCDSA1_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD3 *sess = (ECCDSA1_VrfySessD3*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
	int ret;

	/* Compute zP   */
	ret = EC_POINT_mul(keys->group, sess->zP, sig->z, NULL, NULL, bnctx);

	/* A = (e xor d)X + zP */
	EC_POINT_add(keys->group, sess->A, sess->zP, sess->edX, bnctx);

	/* Convert A to A_bytes */
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		NULL, 0, bnctx);
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		sess->A_bytes, ret, bnctx);

	/* Compute d0_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}
































typedef struct ECCDSA1_SignSessD3b ECCDSA1_SignSessD3b;
struct ECCDSA1_SignSessD3b

{
	BIGNUM*         r;
	EC_POINT*       A;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA1_VrfySessD3b ECCDSA1_VrfySessD3b;
struct ECCDSA1_VrfySessD3b

{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  d0_bytes;
};


void ECCDSA1_d3b_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_SignSessD3b *sess = (ECCDSA1_SignSessD3b*)obj;
	BN_free(sess->r);
	EC_POINT_free(sess->A);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA1_d3b_signsess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;

	ECCDSA1_SignSessD3b *sess = malloc(sizeof(ECCDSA1_SignSessD3b));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA1_SignSessD3b));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d3b_signsess_free(sess);
	return NULL;
}


void ECCDSA1_d3b_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_VrfySessD3b *sess = (ECCDSA1_VrfySessD3b*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->d0_bytes);
	free(sess);
}


void *ECCDSA1_d3b_vrfysess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD3b *sess = malloc(sizeof(ECCDSA1_VrfySessD3b));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA1_VrfySessD3b));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d3b_vrfysess_free(sess);
	return NULL;
}


int ECCDSA1_d3b_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD3b *sess = (ECCDSA1_SignSessD3b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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
		sess->A_bytes, ret, bnctx);

	/* Compute d_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sig->d_bytes, keys->bytelen_go);

	return 0;
}


int ECCDSA1_d3b_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD3b *sess = (ECCDSA1_SignSessD3b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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


int ECCDSA1_d3b_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD3b *sess = (ECCDSA1_VrfySessD3b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	return 0;
}


int ECCDSA1_d3b_vrfy_online(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD3b *sess = (ECCDSA1_VrfySessD3b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
	int ret;

	/* A = zP + (e xor d)X */
	ret = EC_POINT_mul(keys->group, sess->A, sig->z, keys->PK, sess->ed, bnctx);

    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes, ret, bnctx);

    /* Compute d0_bytes = H(A_bytes) */
    PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}
































typedef struct ECCDSA1_SignSessD2 ECCDSA1_SignSessD2;
struct ECCDSA1_SignSessD2
{
	BIGNUM*         r;
	EC_POINT*       A;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA1_VrfySessD2 ECCDSA1_VrfySessD2;
struct ECCDSA1_VrfySessD2
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  d0_bytes;
};


void ECCDSA1_d2_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_SignSessD2 *sess = (ECCDSA1_SignSessD2*)obj;
	BN_free(sess->r);
	EC_POINT_free(sess->A);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA1_d2_signsess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;

	ECCDSA1_SignSessD2 *sess = malloc(sizeof(ECCDSA1_SignSessD2));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA1_SignSessD2));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d2_signsess_free(sess);
	return NULL;
}


void ECCDSA1_d2_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_VrfySessD2 *sess = (ECCDSA1_VrfySessD2*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->d0_bytes);
	free(sess);
}


void *ECCDSA1_d2_vrfysess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD2 *sess = malloc(sizeof(ECCDSA1_VrfySessD2));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA1_VrfySessD2));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d2_vrfysess_free(sess);
	return NULL;
}


int ECCDSA1_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD2 *sess = (ECCDSA1_SignSessD2*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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
		sess->A_bytes, ret, bnctx);

	/* Compute d_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sig->d_bytes, keys->bytelen_go);

	return 0;
}


int ECCDSA1_d2_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD2 *sess = (ECCDSA1_SignSessD2*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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


int ECCDSA1_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj)
{
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD2 *sess = (ECCDSA1_VrfySessD2*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
	int ret;

	return 0;
}


int ECCDSA1_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD2 *sess = (ECCDSA1_VrfySessD2*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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

    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes, ret, bnctx);

    /* Compute d0_bytes = H(A_bytes) */
    PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}



































typedef struct ECCDSA1_SignSessD2b ECCDSA1_SignSessD2b;
struct ECCDSA1_SignSessD2b

{
	BIGNUM*         r;
	EC_POINT*       A;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA1_VrfySessD2b ECCDSA1_VrfySessD2b;
struct ECCDSA1_VrfySessD2b

{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  d0_bytes;
};


void ECCDSA1_d2b_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_SignSessD2b *sess = (ECCDSA1_SignSessD2b*)obj;
	BN_free(sess->r);
	EC_POINT_free(sess->A);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA1_d2b_signsess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;

	ECCDSA1_SignSessD2b *sess = malloc(sizeof(ECCDSA1_SignSessD2b));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA1_SignSessD2b));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d2b_signsess_free(sess);
	return NULL;
}


void ECCDSA1_d2b_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_VrfySessD2b *sess = (ECCDSA1_VrfySessD2b*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->d0_bytes);
	free(sess);
}


void *ECCDSA1_d2b_vrfysess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD2b *sess = malloc(sizeof(ECCDSA1_VrfySessD2b));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA1_VrfySessD2b));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d2b_vrfysess_free(sess);
	return NULL;
}


int ECCDSA1_d2b_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD2b *sess = (ECCDSA1_SignSessD2b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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
		sess->A_bytes, ret, bnctx);

	/* Compute d_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sig->d_bytes, keys->bytelen_go);

	return 0;
}


int ECCDSA1_d2b_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD2b *sess = (ECCDSA1_SignSessD2b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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


int ECCDSA1_d2b_vrfy_offline(void *keyobj, void *sessobj, void *sigobj)
{
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD2b *sess = (ECCDSA1_VrfySessD2b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
	int ret;

	return 0;
}


int ECCDSA1_d2b_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD2b *sess = (ECCDSA1_VrfySessD2b*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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

    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes, ret, bnctx);

    /* Compute d0_bytes = H(A_bytes) */
    PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}



































typedef struct ECCDSA1_SignSessD1 ECCDSA1_SignSessD1;
struct ECCDSA1_SignSessD1
{
	BIGNUM*         r;
	EC_POINT*       A;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA1_VrfySessD1 ECCDSA1_VrfySessD1;
struct ECCDSA1_VrfySessD1
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  d0_bytes;
};



void ECCDSA1_d1_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_SignSessD1 *sess = (ECCDSA1_SignSessD1*)obj;
	BN_free(sess->r);
	EC_POINT_free(sess->A);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA1_d1_signsess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;

	ECCDSA1_SignSessD1 *sess = malloc(sizeof(ECCDSA1_SignSessD1));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA1_SignSessD1));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d1_signsess_free(sess);
	return NULL;
}


void ECCDSA1_d1_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_VrfySessD1 *sess = (ECCDSA1_VrfySessD1*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->d0_bytes);
	free(sess);
}


void *ECCDSA1_d1_vrfysess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD1 *sess = malloc(sizeof(ECCDSA1_VrfySessD1));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA1_VrfySessD1));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d1_vrfysess_free(sess);
	return NULL;
}


int ECCDSA1_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD1 *sess = (ECCDSA1_SignSessD1*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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
		sess->A_bytes, ret, bnctx);

	/* Compute d_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sig->d_bytes, keys->bytelen_go);

	return 0;
}


int ECCDSA1_d1_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD1 *sess = (ECCDSA1_SignSessD1*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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


int ECCDSA1_d1_vrfy_offline(void *keyobj, void *sessobj)
{
	return 0;
}


int ECCDSA1_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD1 *sess = (ECCDSA1_VrfySessD1*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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

    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes, ret, bnctx);

    /* Compute d0_bytes = H(A_bytes) */
    PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}





























typedef struct ECCDSA1_SignSessD0 ECCDSA1_SignSessD0;
struct ECCDSA1_SignSessD0
{
	BIGNUM*         r;
	EC_POINT*       A;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			xed;
};


typedef struct ECCDSA1_VrfySessD0 ECCDSA1_VrfySessD0;
struct ECCDSA1_VrfySessD0
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  d0_bytes;
};


void ECCDSA1_d0_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_SignSessD0 *sess = (ECCDSA1_SignSessD0*)obj;
	BN_free(sess->r);
	EC_POINT_free(sess->A);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->xed);
	free(sess);
}


void *ECCDSA1_d0_signsess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;

	ECCDSA1_SignSessD0 *sess = malloc(sizeof(ECCDSA1_SignSessD0));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECCDSA1_SignSessD0));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->xed = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d0_signsess_free(sess);
	return NULL;
}


void ECCDSA1_d0_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECCDSA1_VrfySessD0 *sess = (ECCDSA1_VrfySessD0*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->d0_bytes);
	free(sess);
}


void *ECCDSA1_d0_vrfysess_new(void *keyobj)
{
	ECCDSA1_KeyPair *keypair = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD0 *sess = malloc(sizeof(ECCDSA1_VrfySessD0));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECCDSA1_VrfySessD0));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECCDSA1_d0_vrfysess_free(sess);
	return NULL;
}


int ECCDSA1_d0_sign(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_SignSessD0 *sess = (ECCDSA1_SignSessD0*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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
		sess->A_bytes, ret, bnctx);

	/* Compute d_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sig->d_bytes, keys->bytelen_go);

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


int ECCDSA1_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECCDSA1_KeyPair *keys = (ECCDSA1_KeyPair*)keyobj;
	ECCDSA1_VrfySessD0 *sess = (ECCDSA1_VrfySessD0*)sessobj;
	ECCDSA1_Sig *sig = (ECCDSA1_Sig*)sigobj;
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

    /* Convert A to A_bytes */
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        NULL, 0, bnctx);
    ret = EC_POINT_point2oct(keys->group,
        sess->A, POINT_CONVERSION_COMPRESSED,
        sess->A_bytes, ret, bnctx);

    /* Compute d0_bytes = H(A_bytes) */
    PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}



























SchemeMethods ECCDSA1_Methods =
{
	.mthd_keypair_new = ECCDSA1_keypair_new,
	.mthd_keypair_free = ECCDSA1_keypair_free,
	.mthd_keypair_gen = ECCDSA1_keypair_gen,
	.mthd_get_name = ECCDSA1_get_name,
	.mthd_signature_new = ECCDSA1_signature_new,
	.mthd_signature_free = ECCDSA1_signature_free,
	.mthd_get_sig_len = ECCDSA1_get_sig_len,
	.mthd_sig_encode = ECCDSA1_sig_encode,

	.mthd_signsess_d3_new = ECCDSA1_d3_signsess_new,
	.mthd_signsess_d3_free = ECCDSA1_d3_signsess_free,
	.mthd_vrfysess_d3_new = ECCDSA1_d3_vrfysess_new,
	.mthd_vrfysess_d3_free = ECCDSA1_d3_vrfysess_free,
	.mthd_d3_sign_offline = ECCDSA1_d3_sign_offline,
	.mthd_d3_sign_online = ECCDSA1_d3_sign_online,
	.mthd_d3_vrfy_offline = ECCDSA1_d3_vrfy_offline,
	.mthd_d3_vrfy_online = ECCDSA1_d3_vrfy_online,

	.mthd_signsess_d3b_new = ECCDSA1_d3b_signsess_new,
	.mthd_signsess_d3b_free = ECCDSA1_d3b_signsess_free,
	.mthd_vrfysess_d3b_new = ECCDSA1_d3b_vrfysess_new,
	.mthd_vrfysess_d3b_free = ECCDSA1_d3b_vrfysess_free,
	.mthd_d3b_sign_offline = ECCDSA1_d3b_sign_offline,
	.mthd_d3b_sign_online = ECCDSA1_d3b_sign_online,
	.mthd_d3b_vrfy_offline = ECCDSA1_d3b_vrfy_offline,
	.mthd_d3b_vrfy_online = ECCDSA1_d3b_vrfy_online,

	.mthd_signsess_d2_new = ECCDSA1_d2_signsess_new,
	.mthd_signsess_d2_free = ECCDSA1_d2_signsess_free,
	.mthd_vrfysess_d2_new = ECCDSA1_d2_vrfysess_new,
	.mthd_vrfysess_d2_free = ECCDSA1_d2_vrfysess_free,
	.mthd_d2_sign_offline = ECCDSA1_d2_sign_offline,
	.mthd_d2_sign_online = ECCDSA1_d2_sign_online,
	.mthd_d2_vrfy_offline = ECCDSA1_d2_vrfy_offline,
	.mthd_d2_vrfy_online = ECCDSA1_d2_vrfy_online,

	.mthd_signsess_d2b_new = ECCDSA1_d2b_signsess_new,
	.mthd_signsess_d2b_free = ECCDSA1_d2b_signsess_free,
	.mthd_vrfysess_d2b_new = ECCDSA1_d2b_vrfysess_new,
	.mthd_vrfysess_d2b_free = ECCDSA1_d2b_vrfysess_free,
	.mthd_d2b_sign_offline = ECCDSA1_d2b_sign_offline,
	.mthd_d2b_sign_online = ECCDSA1_d2b_sign_online,
	.mthd_d2b_vrfy_offline = ECCDSA1_d2b_vrfy_offline,
	.mthd_d2b_vrfy_online = ECCDSA1_d2b_vrfy_online,

	.mthd_signsess_d1_new = ECCDSA1_d1_signsess_new,
	.mthd_signsess_d1_free = ECCDSA1_d1_signsess_free,
	.mthd_vrfysess_d1_new = ECCDSA1_d1_vrfysess_new,
	.mthd_vrfysess_d1_free = ECCDSA1_d1_vrfysess_free,
	.mthd_d1_sign_offline = ECCDSA1_d1_sign_offline,
	.mthd_d1_sign_online = ECCDSA1_d1_sign_online,
	.mthd_d1_vrfy_offline = ECCDSA1_d1_vrfy_offline,
	.mthd_d1_vrfy_online = ECCDSA1_d1_vrfy_online,

	.mthd_signsess_d0_new = ECCDSA1_d0_signsess_new,
	.mthd_signsess_d0_free = ECCDSA1_d0_signsess_free,
	.mthd_vrfysess_d0_new = ECCDSA1_d0_vrfysess_new,
	.mthd_vrfysess_d0_free = ECCDSA1_d0_vrfysess_free,
	.mthd_d0_sign = ECCDSA1_d0_sign,
	.mthd_d0_vrfy = ECCDSA1_d0_vrfy,
};


