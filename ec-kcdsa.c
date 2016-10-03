
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


typedef struct ECKCDSA_KeyPair ECKCDSA_KeyPair;
struct ECKCDSA_KeyPair
{
	EC_KEY*         eckey;
	const EC_GROUP* group;
	BIGNUM*         group_order;
	const BIGNUM*   sk;              // private key
	const EC_POINT* PK;              // public key
	int             bytelen_go;
	int             bytelen_point;
};


typedef struct ECKCDSA_Sig ECKCDSA_Sig;
struct ECKCDSA_Sig
{
	BIGNUM*	d_bytes;
	BIGNUM*	z;
};


typedef struct ECKCDSA_SignSessD3 ECKCDSA_SignSessD3;
struct ECKCDSA_SignSessD3
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			red;
};


typedef struct ECKCDSA_VrfySessD3 ECKCDSA_VrfySessD3;
struct ECKCDSA_VrfySessD3
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       edP;
	EC_POINT*       zX;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  d0_bytes;
};


typedef struct ECKCDSA_SignSessD2 ECKCDSA_SignSessD2;
struct ECKCDSA_SignSessD2
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			red;
};


typedef struct ECKCDSA_VrfySessD2 ECKCDSA_VrfySessD2;
struct ECKCDSA_VrfySessD2
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  d0_bytes;
};


typedef struct ECKCDSA_SignSessD1 ECKCDSA_SignSessD1;
struct ECKCDSA_SignSessD1
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			red;
};


typedef struct ECKCDSA_VrfySessD1 ECKCDSA_VrfySessD1;
struct ECKCDSA_VrfySessD1
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  d0_bytes;
};


typedef struct ECKCDSA_SignSessD0 ECKCDSA_SignSessD0;
struct ECKCDSA_SignSessD0
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	BIGNUM*			red;
};


typedef struct ECKCDSA_VrfySessD0 ECKCDSA_VrfySessD0;
struct ECKCDSA_VrfySessD0
{
	unsigned char*  e_bytes;
	unsigned char*  ed_bytes;
	BIGNUM*         ed;
	EC_POINT*       A;
	unsigned char*  A_bytes;
	unsigned char*  d0_bytes;
};


void *ECKCDSA_keypair_new(int sec);
void ECKCDSA_keypair_free(void *obj);
int ECKCDSA_keypair_gen(int sec, void *obj);
const char *ECKCDSA_get_name();
void *ECKCDSA_signature_new(void *keyobj);
void ECKCDSA_signature_free(void* obj);
int ECKCDSA_get_sig_len(void *obj);
int ECKCDSA_sig_encode(void *obj, unsigned char *buf);

void *ECKCDSA_d3_signsess_new(void *keyobj);
void ECKCDSA_d3_signsess_free(void* obj);
void *ECKCDSA_d3_vrfysess_new(void *keyobj);
void ECKCDSA_d3_vrfysess_free(void* obj);
int ECKCDSA_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECKCDSA_d3_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECKCDSA_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECKCDSA_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj);

void *ECKCDSA_d2_signsess_new(void *keyobj);
void ECKCDSA_d2_signsess_free(void* obj);
void *ECKCDSA_d2_vrfysess_new(void *keyobj);
void ECKCDSA_d2_vrfysess_free(void* obj);
int ECKCDSA_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECKCDSA_d2_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECKCDSA_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj);
int ECKCDSA_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECKCDSA_d1_signsess_new(void *keyobj);
void ECKCDSA_d1_signsess_free(void* obj);
void *ECKCDSA_d1_vrfysess_new(void *keyobj);
void ECKCDSA_d1_vrfysess_free(void* obj);
int ECKCDSA_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECKCDSA_d1_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECKCDSA_d1_vrfy_offline(void *keyobj, void *sessobj);
int ECKCDSA_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECKCDSA_d0_signsess_new(void *keyobj);
void ECKCDSA_d0_signsess_free(void* obj);
void *ECKCDSA_d0_vrfysess_new(void *keyobj);
void ECKCDSA_d0_vrfysess_free(void* obj);
int ECKCDSA_d0_sign(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECKCDSA_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);


SchemeMethods ECKCDSA_Methods =
{
	.mthd_keypair_new = ECKCDSA_keypair_new,
	.mthd_keypair_free = ECKCDSA_keypair_free,
	.mthd_keypair_gen = ECKCDSA_keypair_gen,
	.mthd_get_name = ECKCDSA_get_name,
	.mthd_signature_new = ECKCDSA_signature_new,
	.mthd_signature_free = ECKCDSA_signature_free,
	.mthd_get_sig_len = ECKCDSA_get_sig_len,
	.mthd_sig_encode = ECKCDSA_sig_encode,

	.mthd_signsess_d3_new = ECKCDSA_d3_signsess_new,
	.mthd_signsess_d3_free = ECKCDSA_d3_signsess_free,
	.mthd_vrfysess_d3_new = ECKCDSA_d3_vrfysess_new,
	.mthd_vrfysess_d3_free = ECKCDSA_d3_vrfysess_free,
	.mthd_d3_sign_offline = ECKCDSA_d3_sign_offline,
	.mthd_d3_sign_online = ECKCDSA_d3_sign_online,
	.mthd_d3_vrfy_offline = ECKCDSA_d3_vrfy_offline,
	.mthd_d3_vrfy_online = ECKCDSA_d3_vrfy_online,

	.mthd_signsess_d2_new = ECKCDSA_d2_signsess_new,
	.mthd_signsess_d2_free = ECKCDSA_d2_signsess_free,
	.mthd_vrfysess_d2_new = ECKCDSA_d2_vrfysess_new,
	.mthd_vrfysess_d2_free = ECKCDSA_d2_vrfysess_free,
	.mthd_d2_sign_offline = ECKCDSA_d2_sign_offline,
	.mthd_d2_sign_online = ECKCDSA_d2_sign_online,
	.mthd_d2_vrfy_offline = ECKCDSA_d2_vrfy_offline,
	.mthd_d2_vrfy_online = ECKCDSA_d2_vrfy_online,

	.mthd_signsess_d1_new = ECKCDSA_d1_signsess_new,
	.mthd_signsess_d1_free = ECKCDSA_d1_signsess_free,
	.mthd_vrfysess_d1_new = ECKCDSA_d1_vrfysess_new,
	.mthd_vrfysess_d1_free = ECKCDSA_d1_vrfysess_free,
	.mthd_d1_sign_offline = ECKCDSA_d1_sign_offline,
	.mthd_d1_sign_online = ECKCDSA_d1_sign_online,
	.mthd_d1_vrfy_offline = ECKCDSA_d1_vrfy_offline,
	.mthd_d1_vrfy_online = ECKCDSA_d1_vrfy_online,

	.mthd_signsess_d0_new = ECKCDSA_d0_signsess_new,
	.mthd_signsess_d0_free = ECKCDSA_d0_signsess_free,
	.mthd_vrfysess_d0_new = ECKCDSA_d0_vrfysess_new,
	.mthd_vrfysess_d0_free = ECKCDSA_d0_vrfysess_free,
	.mthd_d0_sign = ECKCDSA_d0_sign,
	.mthd_d0_vrfy = ECKCDSA_d0_vrfy,
};


void *ECKCDSA_keypair_new(int sec)
{
	BIGNUM *w = NULL;
	BIGNUM *group_order = NULL;
	EC_POINT *h = NULL;
	EC_KEY *eckey = NULL;

	ECKCDSA_KeyPair *ret = NULL;

	ret = malloc(sizeof(ECKCDSA_KeyPair));
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


void ECKCDSA_keypair_free(void *obj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)obj;
	EC_KEY_free(keypair->eckey);
	BN_free(keypair->group_order);
	free(keypair);
}


int ECKCDSA_keypair_gen(int sec, void *obj)
{
	int ret = 0;

	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)obj;
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


const char *ECKCDSA_get_name()
{
	return "EC-KCDSA";
}


void *ECKCDSA_signature_new(void *keyobj)
{
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair *)keyobj;
	ECKCDSA_Sig *sig = malloc(sizeof(ECKCDSA_Sig));
	if (sig == NULL) return NULL;

	void *flag = NULL;
	flag = sig->d_bytes = malloc(keys->bytelen_go);if (flag == NULL) goto err;
	flag = sig->z = BN_new();if (flag == NULL) goto err;
	return sig;
err:
	ECKCDSA_signature_free(sig);
	return NULL;
}


void ECKCDSA_signature_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)obj;
	free(sig->d_bytes);
	BN_free(sig->z);
	free(sig);
}



int ECKCDSA_get_sig_len(void *obj)
{
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)obj;
	return -1;//TODO
}


int ECKCDSA_sig_encode(void *obj, unsigned char *buf)
{
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)obj;
	return -1;//TODO
}











void *ECKCDSA_d3_signsess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;

	ECKCDSA_SignSessD3 *sess = malloc(sizeof(ECKCDSA_SignSessD3));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECKCDSA_SignSessD3));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->red = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d3_signsess_free(sess);
	return NULL;
}


void ECKCDSA_d3_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_SignSessD3 *sess = (ECKCDSA_SignSessD3*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->red);
	free(sess);
}


void *ECKCDSA_d3_vrfysess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD3 *sess = malloc(sizeof(ECKCDSA_VrfySessD3));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECKCDSA_VrfySessD3));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->edP = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->zX = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d3_vrfysess_free(sess);
	return NULL;
}


void ECKCDSA_d3_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_VrfySessD3 *sess = (ECKCDSA_VrfySessD3*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->edP);
	EC_POINT_free(sess->zX);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->d0_bytes);
	free(sess);
}


int ECKCDSA_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD3 *sess = (ECKCDSA_SignSessD3*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Pick r */
	ret = BN_rand_range(sess->r, keys->group_order);
	assert(ret == 1);

	/* Compute r^(-1) */
	BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

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


int ECKCDSA_d3_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD3 *sess = (ECKCDSA_SignSessD3*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* Compute r - d xor e */
	BN_mod_sub(sess->red, sess->r, sess->ed, keys->group_order, bnctx);

	/* Compute z=x(r - d xor e) */
	ret = BN_mod_mul(sig->z, keys->sk, sess->red, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECKCDSA_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD3 *sess = (ECKCDSA_VrfySessD3*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* Compute (e xor d)P */
	EC_POINT_mul(keys->group, sess->edP, sess->ed, NULL, NULL, bnctx);

	return 0;
}


int ECKCDSA_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD3 *sess = (ECKCDSA_VrfySessD3*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute zX   */
	ret = EC_POINT_mul(keys->group, sess->zX, NULL, keys->PK, sig->z, bnctx);

	/* A = (e xor d)P + zX */
	EC_POINT_add(keys->group, sess->A, sess->edP, sess->zX, bnctx);

	/* Convert A to A_bytes */
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		NULL, 0, bnctx);
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		sess->A_bytes, ret, bnctx);

	/* d0_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}


































void *ECKCDSA_d2_signsess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;

	ECKCDSA_SignSessD2 *sess = malloc(sizeof(ECKCDSA_SignSessD2));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECKCDSA_SignSessD2));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->red = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d2_signsess_free(sess);
	return NULL;
}


void ECKCDSA_d2_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_SignSessD2 *sess = (ECKCDSA_SignSessD2*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->red);
	free(sess);
}


void *ECKCDSA_d2_vrfysess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD2 *sess = malloc(sizeof(ECKCDSA_VrfySessD2));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECKCDSA_VrfySessD2));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d2_vrfysess_free(sess);
	return NULL;
}


void ECKCDSA_d2_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_VrfySessD2 *sess = (ECKCDSA_VrfySessD2*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->d0_bytes);
	free(sess);
}


int ECKCDSA_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD2 *sess = (ECKCDSA_SignSessD2*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Pick r */
	ret = BN_rand_range(sess->r, keys->group_order);
	assert(ret == 1);

	/* Compute r^(-1) */
	BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

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


int ECKCDSA_d2_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD2 *sess = (ECKCDSA_SignSessD2*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* Compute r - d xor e */
	BN_mod_sub(sess->red, sess->r, sess->ed, keys->group_order, bnctx);

	/* Compute z=x(r - d xor e) */
	ret = BN_mod_mul(sig->z, keys->sk, sess->red, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECKCDSA_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj)
{
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD2 *sess = (ECKCDSA_VrfySessD2*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	return 0;
}


int ECKCDSA_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD2 *sess = (ECKCDSA_VrfySessD2*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* A = (e xor d)P + zX */
	EC_POINT_mul(keys->group, sess->A, sess->ed, keys->PK, sig->z, bnctx);

	/* Convert A to A_bytes */
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		NULL, 0, bnctx);
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		sess->A_bytes, ret, bnctx);

	/* d0_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}





















void *ECKCDSA_d1_signsess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;

	ECKCDSA_SignSessD1 *sess = malloc(sizeof(ECKCDSA_SignSessD1));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECKCDSA_SignSessD1));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->red = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d1_signsess_free(sess);
	return NULL;
}


void ECKCDSA_d1_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_SignSessD1 *sess = (ECKCDSA_SignSessD1*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->red);
	free(sess);
}


void *ECKCDSA_d1_vrfysess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD1 *sess = malloc(sizeof(ECKCDSA_VrfySessD1));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECKCDSA_VrfySessD1));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d1_vrfysess_free(sess);
	return NULL;
}


void ECKCDSA_d1_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_VrfySessD1 *sess = (ECKCDSA_VrfySessD1*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->d0_bytes);
	free(sess);
}


int ECKCDSA_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD1 *sess = (ECKCDSA_SignSessD1*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Pick r */
	ret = BN_rand_range(sess->r, keys->group_order);
	assert(ret == 1);

	/* Compute r^(-1) */
	BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

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


int ECKCDSA_d1_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD1 *sess = (ECKCDSA_SignSessD1*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* Compute r - d xor e */
	BN_mod_sub(sess->red, sess->r, sess->ed, keys->group_order, bnctx);

	/* Compute z=x(r - d xor e) */
	ret = BN_mod_mul(sig->z, keys->sk, sess->red, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECKCDSA_d1_vrfy_offline(void *keyobj, void *sessobj)
{
	return 0;
}


int ECKCDSA_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD1 *sess = (ECKCDSA_VrfySessD1*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* A = (e xor d)P + zX */
	EC_POINT_mul(keys->group, sess->A, sess->ed, keys->PK, sig->z, bnctx);

	/* Convert A to A_bytes */
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		NULL, 0, bnctx);
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		sess->A_bytes, ret, bnctx);

	/* d0_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}
























































void *ECKCDSA_d0_signsess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;

	ECKCDSA_SignSessD0 *sess = malloc(sizeof(ECKCDSA_SignSessD0));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECKCDSA_SignSessD0));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->red = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d0_signsess_free(sess);
	return NULL;
}


void ECKCDSA_d0_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_SignSessD0 *sess = (ECKCDSA_SignSessD0*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	BN_free(sess->red);
	free(sess);
}


void *ECKCDSA_d0_vrfysess_new(void *keyobj)
{
	ECKCDSA_KeyPair *keypair = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD0 *sess = malloc(sizeof(ECKCDSA_VrfySessD0));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECKCDSA_VrfySessD0));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->ed = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A_bytes = malloc(keypair->bytelen_point);if (flag == NULL) goto err;
	flag = sess->d0_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	return sess;
err:
	ECKCDSA_d0_vrfysess_free(sess);
	return NULL;
}


void ECKCDSA_d0_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECKCDSA_VrfySessD0 *sess = (ECKCDSA_VrfySessD0*)obj;
	free(sess->e_bytes);
	free(sess->ed_bytes);
	BN_free(sess->ed);
	EC_POINT_free(sess->A);
	free(sess->A_bytes);
	free(sess->d0_bytes);
	free(sess);
}


int ECKCDSA_d0_sign(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_SignSessD0 *sess = (ECKCDSA_SignSessD0*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Pick r */
	ret = BN_rand_range(sess->r, keys->group_order);
	assert(ret == 1);

	/* Compute r^(-1) */
	BN_mod_inverse(sess->r_inv, sess->r, keys->group_order, bnctx);

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

	/* Compute r - d xor e */
	BN_mod_sub(sess->red, sess->r, sess->ed, keys->group_order, bnctx);

	/* Compute z=x(r - d xor e) */
	ret = BN_mod_mul(sig->z, keys->sk, sess->red, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECKCDSA_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECKCDSA_KeyPair *keys = (ECKCDSA_KeyPair*)keyobj;
	ECKCDSA_VrfySessD0 *sess = (ECKCDSA_VrfySessD0*)sessobj;
	ECKCDSA_Sig *sig = (ECKCDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Compute e_xor_d_bytes */
	BinXor(sig->d_bytes, sess->e_bytes, sess->ed_bytes, keys->bytelen_go);

	/* Convert e_xor_d_bytes to e_xor_d */
	BN_bin2bn(sess->ed_bytes, keys->bytelen_go, sess->ed);

	/* A = (e xor d)P + zX */
	EC_POINT_mul(keys->group, sess->A, sess->ed, keys->PK, sig->z, bnctx);

	/* Convert A to A_bytes */
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		NULL, 0, bnctx);
	ret = EC_POINT_point2oct(keys->group,
		sess->A, POINT_CONVERSION_COMPRESSED,
		sess->A_bytes, ret, bnctx);

	/* d0_bytes = H(A_bytes) */
	PRG(sess->A_bytes, keys->bytelen_point, sess->d0_bytes, keys->bytelen_go);

	/* Check d=d0? */
	ret = BinEq(sig->d_bytes, sess->d0_bytes, keys->bytelen_go);
	if (ret != 0) return -1;

	return 0;
}


