#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#include "scheme.h"


Scheme *Scheme_new(SchemeMethods *methods)
{
    if (methods == NULL) return NULL;

    Scheme *ret = malloc(sizeof(Scheme));
    ret->imp = methods;
    return ret;
err:
    Scheme_free(ret);
    return NULL;
}


KeyPair *KeyPair_new(Scheme *sch, int sec)
{
    if (sch == NULL) return NULL;
    KeyPair *ret = (KeyPair*)malloc(sizeof(KeyPair));
    void *obj = sch->imp->mthd_keypair_new(sec);
    if (obj == NULL) goto err;
    ret->sch = sch;
    ret->sec = sec;
    ret->obj = obj;
    return ret;
err:
    KeyPair_free(ret);
    return NULL;
}


void KeyPair_free(KeyPair *keypair)
{
    if (keypair == NULL) return;
    keypair->sch->imp->mthd_keypair_free(keypair->obj);
    free(keypair);
}


int KeyPair_gen(KeyPair *keypair)
{
    if (keypair == NULL) return -1;
    int sec = keypair->sec;
    void *obj = keypair->obj;
    return keypair->sch->imp->mthd_keypair_gen(sec, obj);
}


Signature *Signature_new(KeyPair *keypair, Scheme *sch)
{
    if (sch == NULL) return NULL;
    Signature *ret = (Signature*)malloc(sizeof(Signature));
    ret->sch = sch;
    void *keyobj = keypair->obj;
    void *obj = sch->imp->mthd_signature_new(keyobj);
    if (obj == NULL) goto err;
    ret->obj = obj;
    return ret;
err:
    Signature_free(ret);
    return NULL;
}


void Signature_free(Signature *sig)
{
    if (sig == NULL) return;
    sig->sch->imp->mthd_signature_free(sig->obj);
    free(sig);
}


int Signature_get_length(Signature *sig)
{
    if (sig == NULL) return -1;
    return sig->sch->imp->mthd_get_sig_len(sig->obj);
}


int Signature_encode(Signature *sig, unsigned char *buf)
{
    if (sig == NULL) return -1;
    if (buf == NULL) return -1;
    return sig->sch->imp->mthd_sig_encode(sig->obj, buf);
}


void Scheme_free(Scheme *sch)
{
    if (sch == NULL) return;
    free(sch);
}


const unsigned char *Scheme_get_name(Scheme *sch)
{
    return sch->imp->mthd_get_name();
}


SignSessionD3 *SignSessionD3_new(KeyPair *keypair, Scheme *sch)
{
	if (keypair == NULL) return NULL;
	if (sch == NULL) return NULL;
	SignSessionD3 *ret = (SignSessionD3*)malloc(sizeof(SignSessionD3));
	ret->sch = sch;
	void *obj = sch->imp->mthd_signsess_d3_new(keypair->obj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;
err:
	SignSessionD3_free(ret);
	return NULL;
}


void SignSessionD3_free(SignSessionD3 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_signsess_d3_free(sess->obj);
	free(sess);
}


VrfySessionD3 *VrfySessionD3_new(KeyPair *keypair, Scheme *sch)
{
	if (sch == NULL) return NULL;
	VrfySessionD3 *ret = (VrfySessionD3*)malloc(sizeof(VrfySessionD3));
	ret->sch = sch;
	void *keyobj = keypair->obj;
	void *obj = sch->imp->mthd_vrfysess_d3_new(keyobj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;

err:
	VrfySessionD3_free(ret);
	return NULL;
}


void VrfySessionD3_free(VrfySessionD3 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_vrfysess_d3_free(sess->obj);
	free(sess);
}


int Scheme_D3_sign_offline(Scheme *sch, KeyPair *keypair,
        SignSessionD3 *sess, Signature *sig)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    if (sig == NULL) return -1;
    return sch->imp->mthd_d3_sign_offline(keypair->obj, sess->obj, sig->obj);
}


int Scheme_D3_sign_online(Scheme *sch, KeyPair *keypair,
        SignSessionD3 *sess, Signature *sig,
        const unsigned char *msg, int msglen)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    if (sig == NULL) return -1;
    if (msg == NULL) return -1;
    return sch->imp->mthd_d3_sign_online(
			keypair->obj, sess->obj,
			sig->obj, msg, msglen);
}


int Scheme_D3_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySessionD3 *sess,
	Signature *sig, const unsigned char *msg, int msglen)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    return sch->imp->mthd_d3_vrfy_offline(keypair->obj, sess->obj,
			sig->obj, msg, msglen);
}


int Scheme_D3_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySessionD3 *sess,
        Signature *sig)
{
    if (sch == NULL) return -1;
    if (keypair == NULL) return -1;
    if (sess == NULL) return -1;
    if (sig == NULL) return -1;
    return sch->imp->mthd_d3_vrfy_online(keypair->obj, sess->obj, sig->obj);
}










SignSessionD2 *SignSessionD2_new(KeyPair *keypair, Scheme *sch)
{
	if (keypair == NULL) return NULL;
	if (sch == NULL) return NULL;
	SignSessionD2 *ret = (SignSessionD2*)malloc(sizeof(SignSessionD2));
	ret->sch = sch;
	void *obj = sch->imp->mthd_signsess_d2_new(keypair->obj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;
err:
	SignSessionD2_free(ret);
	return NULL;
}


void SignSessionD2_free(SignSessionD2 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_signsess_d2_free(sess->obj);
	free(sess);
}


VrfySessionD2 *VrfySessionD2_new(KeyPair *keypair, Scheme *sch)
{
	if (sch == NULL) return NULL;
	VrfySessionD2 *ret = (VrfySessionD2*)malloc(sizeof(VrfySessionD2));
	ret->sch = sch;
	void *keyobj = keypair->obj;
	void *obj = sch->imp->mthd_vrfysess_d2_new(keyobj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;

err:
	VrfySessionD2_free(ret);
	return NULL;
}


void VrfySessionD2_free(VrfySessionD2 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_vrfysess_d2_free(sess->obj);
	free(sess);
}


int Scheme_D2_sign_offline(Scheme *sch, KeyPair *keypair,
	SignSessionD2 *sess, Signature *sig)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	return sch->imp->mthd_d2_sign_offline(keypair->obj, sess->obj, sig->obj);
}


int Scheme_D2_sign_online(Scheme *sch, KeyPair *keypair,
	SignSessionD2 *sess, Signature *sig,
	const unsigned char *msg, int msglen)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	if (msg == NULL) return -1;
	return sch->imp->mthd_d2_sign_online(
		keypair->obj, sess->obj,
		sig->obj, msg, msglen);
}


int Scheme_D2_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySessionD2 *sess,
	Signature *sig)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	return sch->imp->mthd_d2_vrfy_offline(keypair->obj, sess->obj,
		sig->obj);
}


int Scheme_D2_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySessionD2 *sess,
	Signature *sig, const unsigned char *msg, int msglen)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	return sch->imp->mthd_d2_vrfy_online(keypair->obj, sess->obj, sig->obj, msg, msglen);
}










SignSessionD1 *SignSessionD1_new(KeyPair *keypair, Scheme *sch)
{
	if (keypair == NULL) return NULL;
	if (sch == NULL) return NULL;
	SignSessionD1 *ret = (SignSessionD1*)malloc(sizeof(SignSessionD1));
	ret->sch = sch;
	void *obj = sch->imp->mthd_signsess_d1_new(keypair->obj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;
err:
	SignSessionD1_free(ret);
	return NULL;
}


void SignSessionD1_free(SignSessionD1 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_signsess_d1_free(sess->obj);
	free(sess);
}


VrfySessionD1 *VrfySessionD1_new(KeyPair *keypair, Scheme *sch)
{
	if (sch == NULL) return NULL;
	VrfySessionD1 *ret = (VrfySessionD1*)malloc(sizeof(VrfySessionD1));
	ret->sch = sch;
	void *keyobj = keypair->obj;
	void *obj = sch->imp->mthd_vrfysess_d1_new(keyobj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;

err:
	VrfySessionD1_free(ret);
	return NULL;
}


void VrfySessionD1_free(VrfySessionD1 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_vrfysess_d1_free(sess->obj);
	free(sess);
}


int Scheme_D1_sign_offline(Scheme *sch, KeyPair *keypair,
	SignSessionD1 *sess, Signature *sig)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	return sch->imp->mthd_d1_sign_offline(keypair->obj, sess->obj, sig->obj);
}


int Scheme_D1_sign_online(Scheme *sch, KeyPair *keypair,
	SignSessionD1 *sess, Signature *sig,
	const unsigned char *msg, int msglen)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	if (msg == NULL) return -1;
	return sch->imp->mthd_d1_sign_online(
		keypair->obj, sess->obj,
		sig->obj, msg, msglen);
}


int Scheme_D1_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySessionD1 *sess)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	return sch->imp->mthd_d1_vrfy_offline(keypair->obj, sess->obj);
}


int Scheme_D1_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySessionD1 *sess,
	Signature *sig, const unsigned char *msg, int msglen)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	return sch->imp->mthd_d1_vrfy_online(keypair->obj, sess->obj, sig->obj, msg, msglen);
}










SignSessionD0 *SignSessionD0_new(KeyPair *keypair, Scheme *sch)
{
	if (keypair == NULL) return NULL;
	if (sch == NULL) return NULL;
	SignSessionD0 *ret = (SignSessionD0*)malloc(sizeof(SignSessionD0));
	ret->sch = sch;
	void *obj = sch->imp->mthd_signsess_d0_new(keypair->obj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;
err:
	SignSessionD0_free(ret);
	return NULL;
}


void SignSessionD0_free(SignSessionD0 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_signsess_d0_free(sess->obj);
	free(sess);
}


VrfySessionD0 *VrfySessionD0_new(KeyPair *keypair, Scheme *sch)
{
	if (sch == NULL) return NULL;
	VrfySessionD0 *ret = (VrfySessionD0*)malloc(sizeof(VrfySessionD0));
	ret->sch = sch;
	void *keyobj = keypair->obj;
	void *obj = sch->imp->mthd_vrfysess_d0_new(keyobj);
	if (obj == NULL) goto err;
	ret->obj = obj;
	return ret;

err:
	VrfySessionD0_free(ret);
	return NULL;
}


void VrfySessionD0_free(VrfySessionD0 *sess)
{
	if (sess == NULL) return;
	sess->sch->imp->mthd_vrfysess_d0_free(sess->obj);
	free(sess);
}


int Scheme_D0_sign(Scheme *sch, KeyPair *keypair,
	SignSessionD0 *sess, Signature *sig,
	const unsigned char *msg, int msglen)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	if (sig == NULL) return -1;
	if (msg == NULL) return -1;
	return sch->imp->mthd_d0_sign(
		keypair->obj, sess->obj,
		sig->obj, msg, msglen);
}


int Scheme_D0_vrfy(Scheme *sch, KeyPair *keypair, VrfySessionD0 *sess,
	Signature *sig, const unsigned char *msg, int msglen)
{
	if (sch == NULL) return -1;
	if (keypair == NULL) return -1;
	if (sess == NULL) return -1;
	return sch->imp->mthd_d0_vrfy(keypair->obj, sess->obj,
		sig->obj, msg, msglen);
}
