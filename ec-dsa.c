
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


typedef struct ECDSA_KeyPair ECDSA_KeyPair;
struct ECDSA_KeyPair
{
	EC_KEY*         eckey;
	const EC_GROUP* group;
	BIGNUM*         group_order;
	const BIGNUM*   sk;              // private key
	const EC_POINT* PK;              // public key
	int             bytelen_go;
	int             bytelen_point;
};


typedef struct ECDSA_Sig ECDSA_Sig;
struct ECDSA_Sig
{
	BIGNUM*	d;
	BIGNUM*	z;
};


typedef struct ECDSA_SignSessD3 ECDSA_SignSessD3;
struct ECDSA_SignSessD3
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	BIGNUM*			dx;
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			edx;
};


typedef struct ECDSA_VrfySessD3 ECDSA_VrfySessD3;
struct ECDSA_VrfySessD3
{
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			z_inv;
	EC_POINT*       A0;
	EC_POINT*       A;
	BIGNUM*			d0;
};


typedef struct ECDSA_SignSessD2 ECDSA_SignSessD2;
struct ECDSA_SignSessD2
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	BIGNUM*			dx;
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			edx;
};


typedef struct ECDSA_VrfySessD2 ECDSA_VrfySessD2;
struct ECDSA_VrfySessD2
{
	EC_POINT*       dX;
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			z_inv;
	EC_POINT*       A;
	BIGNUM*			d0;
	BIGNUM*			z_inv_e;
};


typedef struct ECDSA_SignSessD1 ECDSA_SignSessD1;
struct ECDSA_SignSessD1
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	BIGNUM*			dx;
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			edx;
};


typedef struct ECDSA_VrfySessD1 ECDSA_VrfySessD1;
struct ECDSA_VrfySessD1
{
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			z_inv;
	BIGNUM*			z_inv_e;
	BIGNUM*			z_inv_d;
	EC_POINT*       A0;
	EC_POINT*       A;
	BIGNUM*			d0;
};


typedef struct ECDSA_SignSessD0 ECDSA_SignSessD0;
struct ECDSA_SignSessD0
{
	BIGNUM*         r;
	BIGNUM*			r_inv;
	EC_POINT*       A;
	BIGNUM*			dx;
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			edx;
};


typedef struct ECDSA_VrfySessD0 ECDSA_VrfySessD0;
struct ECDSA_VrfySessD0
{
	unsigned char*  e_bytes;
	BIGNUM*         e;
	BIGNUM*			z_inv;
	BIGNUM*			z_inv_e;
	BIGNUM*			z_inv_d;
	EC_POINT*       A0;
	EC_POINT*       A;
	BIGNUM*			d0;
};


void *ECDSA_keypair_new(int sec);
void ECDSA_keypair_free(void *obj);
int ECDSA_keypair_gen(int sec, void *obj);
const char *ECDSA_get_name();
void *ECDSA_signature_new(void *keyobj);
void ECDSA_signature_free(void* obj);
int ECDSA_get_sig_len(void *obj);
int ECDSA_sig_encode(void *obj, unsigned char *buf);

void *ECDSA_d3_signsess_new(void *keyobj);
void ECDSA_d3_signsess_free(void* obj);
void *ECDSA_d3_vrfysess_new(void *keyobj);
void ECDSA_d3_vrfysess_free(void* obj);
int ECDSA_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECDSA_d3_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECDSA_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECDSA_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj);

void *ECDSA_d2_signsess_new(void *keyobj);
void ECDSA_d2_signsess_free(void* obj);
void *ECDSA_d2_vrfysess_new(void *keyobj);
void ECDSA_d2_vrfysess_free(void* obj);
int ECDSA_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECDSA_d2_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECDSA_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj);
int ECDSA_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECDSA_d1_signsess_new(void *keyobj);
void ECDSA_d1_signsess_free(void* obj);
void *ECDSA_d1_vrfysess_new(void *keyobj);
void ECDSA_d1_vrfysess_free(void* obj);
int ECDSA_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj);
int ECDSA_d1_sign_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECDSA_d1_vrfy_offline(void *keyobj, void *sessobj);
int ECDSA_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);

void *ECDSA_d0_signsess_new(void *keyobj);
void ECDSA_d0_signsess_free(void* obj);
void *ECDSA_d0_vrfysess_new(void *keyobj);
void ECDSA_d0_vrfysess_free(void* obj);
int ECDSA_d0_sign(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);
int ECDSA_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen);


SchemeMethods ECDSA_Methods =
{
	.mthd_keypair_new = ECDSA_keypair_new,
	.mthd_keypair_free = ECDSA_keypair_free,
	.mthd_keypair_gen = ECDSA_keypair_gen,
	.mthd_get_name = ECDSA_get_name,
	.mthd_signature_new = ECDSA_signature_new,
	.mthd_signature_free = ECDSA_signature_free,
	.mthd_get_sig_len = ECDSA_get_sig_len,
	.mthd_sig_encode = ECDSA_sig_encode,

	.mthd_signsess_d3_new = ECDSA_d3_signsess_new,
	.mthd_signsess_d3_free = ECDSA_d3_signsess_free,
	.mthd_vrfysess_d3_new = ECDSA_d3_vrfysess_new,
	.mthd_vrfysess_d3_free = ECDSA_d3_vrfysess_free,
	.mthd_d3_sign_offline = ECDSA_d3_sign_offline,
	.mthd_d3_sign_online = ECDSA_d3_sign_online,
	.mthd_d3_vrfy_offline = ECDSA_d3_vrfy_offline,
	.mthd_d3_vrfy_online = ECDSA_d3_vrfy_online,

	.mthd_signsess_d2_new = ECDSA_d2_signsess_new,
	.mthd_signsess_d2_free = ECDSA_d2_signsess_free,
	.mthd_vrfysess_d2_new = ECDSA_d2_vrfysess_new,
	.mthd_vrfysess_d2_free = ECDSA_d2_vrfysess_free,
	.mthd_d2_sign_offline = ECDSA_d2_sign_offline,
	.mthd_d2_sign_online = ECDSA_d2_sign_online,
	.mthd_d2_vrfy_offline = ECDSA_d2_vrfy_offline,
	.mthd_d2_vrfy_online = ECDSA_d2_vrfy_online,

	.mthd_signsess_d1_new = ECDSA_d1_signsess_new,
	.mthd_signsess_d1_free = ECDSA_d1_signsess_free,
	.mthd_vrfysess_d1_new = ECDSA_d1_vrfysess_new,
	.mthd_vrfysess_d1_free = ECDSA_d1_vrfysess_free,
	.mthd_d1_sign_offline = ECDSA_d1_sign_offline,
	.mthd_d1_sign_online = ECDSA_d1_sign_online,
	.mthd_d1_vrfy_offline = ECDSA_d1_vrfy_offline,
	.mthd_d1_vrfy_online = ECDSA_d1_vrfy_online,

	.mthd_signsess_d0_new = ECDSA_d0_signsess_new,
	.mthd_signsess_d0_free = ECDSA_d0_signsess_free,
	.mthd_vrfysess_d0_new = ECDSA_d0_vrfysess_new,
	.mthd_vrfysess_d0_free = ECDSA_d0_vrfysess_free,
	.mthd_d0_sign = ECDSA_d0_sign,
	.mthd_d0_vrfy = ECDSA_d0_vrfy,
};


void *ECDSA_keypair_new(int sec)
{
	BIGNUM *w = NULL;
	BIGNUM *group_order = NULL;
	EC_POINT *h = NULL;
	EC_KEY *eckey = NULL;

	ECDSA_KeyPair *ret = NULL;

	ret = malloc(sizeof(ECDSA_KeyPair));
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


void ECDSA_keypair_free(void *obj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)obj;
	EC_KEY_free(keypair->eckey);
	BN_free(keypair->group_order);
	free(keypair);
}


int ECDSA_keypair_gen(int sec, void *obj)
{
	int ret = 0;

	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)obj;
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


const char *ECDSA_get_name()
{
	return "ECDSA";
}


void *ECDSA_signature_new(void *keyobj)
{
	ECDSA_Sig *sig = malloc(sizeof(ECDSA_Sig));
	if (sig == NULL) return NULL;

	void *flag = NULL;
	flag = sig->d = BN_new();if (flag == NULL) goto err;
	flag = sig->z = BN_new();if (flag == NULL) goto err;
	return sig;
err:
	ECDSA_signature_free(sig);
	return NULL;
}


void ECDSA_signature_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_Sig *sig = (ECDSA_Sig*)obj;
	BN_free(sig->d);
	BN_free(sig->z);
	free(sig);
}



int ECDSA_get_sig_len(void *obj)
{
	ECDSA_Sig *sig = (ECDSA_Sig*)obj;
	return -1;//TODO
}


int ECDSA_sig_encode(void *obj, unsigned char *buf)
{
	ECDSA_Sig *sig = (ECDSA_Sig*)obj;
	return -1;//TODO
}











void *ECDSA_d3_signsess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;

	ECDSA_SignSessD3 *sess = malloc(sizeof(ECDSA_SignSessD3));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECDSA_SignSessD3));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->dx = BN_new();if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->edx = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d3_signsess_free(sess);
	return NULL;
}


void ECDSA_d3_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_SignSessD3 *sess = (ECDSA_SignSessD3*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	BN_free(sess->dx);
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->edx);
	free(sess);
}


void *ECDSA_d3_vrfysess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD3 *sess = malloc(sizeof(ECDSA_VrfySessD3));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECDSA_VrfySessD3));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A0 = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0 = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d3_vrfysess_free(sess);
	return NULL;
}


void ECDSA_d3_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_VrfySessD3 *sess = (ECDSA_VrfySessD3*)obj;
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->z_inv);
	EC_POINT_free(sess->A0);
	EC_POINT_free(sess->A);
	BN_free(sess->d0);
	free(sess);
}


int ECDSA_d3_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD3 *sess = (ECDSA_SignSessD3*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
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


int ECDSA_d3_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD3 *sess = (ECDSA_SignSessD3*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute z=r^(-1) * (e+dx) */
	ret = BN_mod_add(sess->edx, sess->e, sess->dx, keys->group_order, bnctx);
	assert(ret == 1);
	
    ret = BN_mod_mul(sig->z, sess->r_inv, sess->edx, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECDSA_d3_vrfy_offline(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD3 *sess = (ECDSA_VrfySessD3*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute A0 = eP+dX */
	EC_POINT_mul(keys->group, sess->A0, sess->e, keys->PK, sig->d, bnctx);
    
	return 0;
}


int ECDSA_d3_vrfy_online(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD3 *sess = (ECDSA_VrfySessD3*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute z^(-1) */
	BN_mod_inverse(sess->z_inv, sig->z, keys->group_order, bnctx);

	/* Compute A = z^(-1) * A0   */
	ret = EC_POINT_mul(keys->group, sess->A, NULL, sess->A0, sess->z_inv, bnctx);
        
	/* Let d0 = A0.x */
	ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);
        
	/* Check d=d0? */
	ret = BN_cmp(sig->d, sess->d0);
	if (ret != 0) return -1;

	return 0;
}






void *ECDSA_d2_signsess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;

	ECDSA_SignSessD2 *sess = malloc(sizeof(ECDSA_SignSessD2));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECDSA_SignSessD2));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->dx = BN_new();if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->edx = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d2_signsess_free(sess);
	return NULL;
}


void ECDSA_d2_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_SignSessD2 *sess = (ECDSA_SignSessD2*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	BN_free(sess->dx);
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->edx);
	free(sess);
}


void *ECDSA_d2_vrfysess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD2 *sess = malloc(sizeof(ECDSA_VrfySessD2));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECDSA_VrfySessD2));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->dX = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0 = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv_e = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d2_vrfysess_free(sess);
	return NULL;
}


void ECDSA_d2_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_VrfySessD2 *sess = (ECDSA_VrfySessD2*)obj;
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->z_inv);
	EC_POINT_free(sess->A);
	EC_POINT_free(sess->dX);
	BN_free(sess->d0);
	BN_free(sess->z_inv_e);
	free(sess);
}


int ECDSA_d2_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD2 *sess = (ECDSA_SignSessD2*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
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


int ECDSA_d2_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD2 *sess = (ECDSA_SignSessD2*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute z=r^(-1) * (e+dx) */
	ret = BN_mod_add(sess->edx, sess->e, sess->dx, keys->group_order, bnctx);
	assert(ret == 1);

	ret = BN_mod_mul(sig->z, sess->r_inv, sess->edx, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECDSA_d2_vrfy_offline(void *keyobj, void *sessobj, void *sigobj)
{
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD2 *sess = (ECDSA_VrfySessD2*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute EC point dX */
	EC_POINT_mul(keys->group, sess->dX, NULL, keys->PK, sig->d, bnctx);

	return 0;
}


int ECDSA_d2_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD2 *sess = (ECDSA_VrfySessD2*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute z^(-1) */
	BN_mod_inverse(sess->z_inv, sig->z, keys->group_order, bnctx);

	/* Compute z^(-1)e */
	BN_mod_mul(sess->z_inv_e, sess->z_inv, sess->e, keys->group_order, bnctx);

	/* Compute A = z^(-1)e * P + z^(-1)(dX)  */
	ret = EC_POINT_mul(keys->group, sess->A, sess->z_inv_e, sess->dX, sess->z_inv, bnctx);

	/* Let d0 = A.x */
	ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

	/* Check d=d0? */
	ret = BN_cmp(sig->d, sess->d0);
	if (ret != 0) return -1;

	return 0;
}











void *ECDSA_d1_signsess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;

	ECDSA_SignSessD1 *sess = malloc(sizeof(ECDSA_SignSessD1));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECDSA_SignSessD1));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->dx = BN_new();if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->edx = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d1_signsess_free(sess);
	return NULL;
}


void ECDSA_d1_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_SignSessD1 *sess = (ECDSA_SignSessD1*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	BN_free(sess->dx);
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->edx);
	free(sess);
}


void *ECDSA_d1_vrfysess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD1 *sess = malloc(sizeof(ECDSA_VrfySessD1));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECDSA_VrfySessD1));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0 = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv_e = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv_d = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d1_vrfysess_free(sess);
	return NULL;
}


void ECDSA_d1_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_VrfySessD1 *sess = (ECDSA_VrfySessD1*)obj;
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->z_inv);
	BN_free(sess->z_inv_d);
	BN_free(sess->z_inv_e);
	EC_POINT_free(sess->A);
	BN_free(sess->d0);
	free(sess);
}


int ECDSA_d1_sign_offline(void *keyobj, void *sessobj, void *sigobj)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD1 *sess = (ECDSA_SignSessD1*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
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


int ECDSA_d1_sign_online(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD1 *sess = (ECDSA_SignSessD1*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute z=r^(-1) * (e+dx) */
	ret = BN_mod_add(sess->edx, sess->e, sess->dx, keys->group_order, bnctx);
	assert(ret == 1);

	ret = BN_mod_mul(sig->z, sess->r_inv, sess->edx, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECDSA_d1_vrfy_offline(void *keyobj, void *sessobj)
{
	return 0;
}


int ECDSA_d1_vrfy_online(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD1 *sess = (ECDSA_VrfySessD1*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute z^(-1) */
	BN_mod_inverse(sess->z_inv, sig->z, keys->group_order, bnctx);

	/* Compute z^(-1)e */
	BN_mod_mul(sess->z_inv_e, sess->z_inv, sess->e, keys->group_order, bnctx);

	/* Compute z^(-1)d */
	BN_mod_mul(sess->z_inv_d, sess->z_inv, sig->d, keys->group_order, bnctx);

	/* Compute A = z^(-1)e * P + z^(-1)d X  */
	ret = EC_POINT_mul(keys->group, sess->A, sess->z_inv_e, keys->PK, sess->z_inv_d, bnctx);

	/* Let d0 = A.x */
	ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

	/* Check d=d0? */
	ret = BN_cmp(sig->d, sess->d0);
	if (ret != 0) return -1;

	return 0;
}























void *ECDSA_d0_signsess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;

	ECDSA_SignSessD0 *sess = malloc(sizeof(ECDSA_SignSessD0));
	if (sess == NULL) return NULL;

	memset(sess, 0, sizeof(ECDSA_SignSessD0));

	void *flag = NULL;
	flag = sess->r = BN_new();if (flag == NULL) goto err;
	flag = sess->r_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->dx = BN_new();if (flag == NULL) goto err;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->edx = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d0_signsess_free(sess);
	return NULL;
}


void ECDSA_d0_signsess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_SignSessD0 *sess = (ECDSA_SignSessD0*)obj;
	BN_free(sess->r);
	BN_free(sess->r_inv);
	EC_POINT_free(sess->A);
	BN_free(sess->dx);
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->edx);
	free(sess);
}


void *ECDSA_d0_vrfysess_new(void *keyobj)
{
	ECDSA_KeyPair *keypair = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD0 *sess = malloc(sizeof(ECDSA_VrfySessD0));
	if (sess == NULL) return NULL;
	memset(sess, 0, sizeof(ECDSA_VrfySessD0));

	void *flag = NULL;
	flag = sess->e_bytes = malloc(keypair->bytelen_go);if (flag == NULL) goto err;
	flag = sess->e = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv = BN_new();if (flag == NULL) goto err;
	flag = sess->A = EC_POINT_new(keypair->group);if (flag == NULL) goto err;
	flag = sess->d0 = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv_e = BN_new();if (flag == NULL) goto err;
	flag = sess->z_inv_d = BN_new();if (flag == NULL) goto err;
	return sess;
err:
	ECDSA_d0_vrfysess_free(sess);
	return NULL;
}


void ECDSA_d0_vrfysess_free(void* obj)
{
	if (obj == NULL) return;
	ECDSA_VrfySessD0 *sess = (ECDSA_VrfySessD0*)obj;
	free(sess->e_bytes);
	BN_free(sess->e);
	BN_free(sess->z_inv);
	BN_free(sess->z_inv_d);
	BN_free(sess->z_inv_e);
	EC_POINT_free(sess->A);
	BN_free(sess->d0);
	free(sess);
}


int ECDSA_d0_sign(void *keyobj, void *sessobj, void *sigobj,
	const unsigned char *msg, int msglen)
{
	/* Cast objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_SignSessD0 *sess = (ECDSA_SignSessD0*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
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

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute dx */
	BN_mod_mul(sess->dx, sig->d, keys->sk, keys->group_order, bnctx);

	/* Compute z=r^(-1) * (e+dx) */
	ret = BN_mod_add(sess->edx, sess->e, sess->dx, keys->group_order, bnctx);
	assert(ret == 1);

	ret = BN_mod_mul(sig->z, sess->r_inv, sess->edx, keys->group_order, bnctx);
	assert(ret == 1);

	return 0;
}


int ECDSA_d0_vrfy(void *keyobj, void *sessobj, void *sigobj, const unsigned char *msg, int msglen)
{
	/* Rename objects. */
	ECDSA_KeyPair *keys = (ECDSA_KeyPair*)keyobj;
	ECDSA_VrfySessD0 *sess = (ECDSA_VrfySessD0*)sessobj;
	ECDSA_Sig *sig = (ECDSA_Sig*)sigobj;
	int ret;

	/* Compute e_bytes = H(m) */
	PRG(msg, msglen, sess->e_bytes, keys->bytelen_go);

	/* Convert e_bytes to e */
	BN_bin2bn(sess->e_bytes, keys->bytelen_go, sess->e);

	/* Compute z^(-1) */
	BN_mod_inverse(sess->z_inv, sig->z, keys->group_order, bnctx);

	/* Compute z^(-1)e */
	BN_mod_mul(sess->z_inv_e, sess->z_inv, sess->e, keys->group_order, bnctx);

	/* Compute z^(-1)d */
	BN_mod_mul(sess->z_inv_d, sess->z_inv, sig->d, keys->group_order, bnctx);

	/* Compute A = z^(-1)e * P + z^(-1)d X  */
	ret = EC_POINT_mul(keys->group, sess->A, sess->z_inv_e, keys->PK, sess->z_inv_d, bnctx);

	/* Let d0 = A.x */
	ret = EC_POINT_get_affine_coordinates_GFp(keys->group, sess->A, sess->d0, NULL, bnctx);

	/* Check d=d0? */
	ret = BN_cmp(sig->d, sess->d0);
	if (ret != 0) return -1;

	return 0;
}


