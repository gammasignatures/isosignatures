#ifndef __SCHEME_H__
#define __SCHEME_H__


typedef struct SchemeMethods SchemeMethods;
struct SchemeMethods
{
    void *(*mthd_keypair_new)(int sec);
    void (*mthd_keypair_free)(void *obj);
    int (*mthd_keypair_gen)(int sec, void *obj);
    const char *(*mthd_get_name)();
    void *(*mthd_signature_new)(void *keyobj);
    void (*mthd_signature_free)(void* obj);
    int (*mthd_get_sig_len)(void *obj);
    int (*mthd_sig_encode)(void *obj, unsigned char *buf);

	/* Deployment-3 related fields */
	void *(*mthd_signsess_d3_new)(void *keyobj);
	void(*mthd_signsess_d3_free)(void* obj);
	void *(*mthd_vrfysess_d3_new)(void *keyobj);
	void(*mthd_vrfysess_d3_free)(void* obj);
	int(*mthd_d3_sign_offline)(void *keyobj, void *sessobj, void *sigobj);
	int(*mthd_d3_sign_online)(void *keyobj, void *sessobj, void *sigobj,
		const unsigned char *msg, int msglen);
	int(*mthd_d3_vrfy_offline)(void *keyobj, void *sessobj, void *sigobj,
		const unsigned char *msg, int msglen);
	int(*mthd_d3_vrfy_online)(void *keyobj, void *sessobj, void *sigobj);

	/* Deployment-2 related fields */
	void *(*mthd_signsess_d2_new)(void *keyobj);
	void(*mthd_signsess_d2_free)(void* obj);
	void *(*mthd_vrfysess_d2_new)(void *keyobj);
	void(*mthd_vrfysess_d2_free)(void* obj);
	int(*mthd_d2_sign_offline)(void *keyobj, void *sessobj, void *sigobj);
	int(*mthd_d2_sign_online)(void *keyobj, void *sessobj, void *sigobj,
		const unsigned char *msg, int msglen);
	int(*mthd_d2_vrfy_offline)(void *keyobj, void *sessobj, void *sigobj);
	int(*mthd_d2_vrfy_online)(void *keyobj, void *sessobj, void *sigobj,
		const unsigned char *msg, int msglen);

	/* Deployment-1 related fields */
	void *(*mthd_signsess_d1_new)(void *keyobj);
	void(*mthd_signsess_d1_free)(void* obj);
	void *(*mthd_vrfysess_d1_new)(void *keyobj);
	void(*mthd_vrfysess_d1_free)(void* obj);
	int(*mthd_d1_sign_offline)(void *keyobj, void *sessobj, void *sigobj);
	int(*mthd_d1_sign_online)(void *keyobj, void *sessobj,
		void *sigobj, const unsigned char *msg, int msglen);
	int(*mthd_d1_vrfy_offline)(void *keyobj, void *sessobj);
	int(*mthd_d1_vrfy_online)(void *keyobj, void *sessobj,
		void *sigobj, const unsigned char *msg, int msglen);

	/* Deployment-0 related fields */
	void *(*mthd_signsess_d0_new)(void *keyobj);
	void(*mthd_signsess_d0_free)(void* obj);
	void *(*mthd_vrfysess_d0_new)(void *keyobj);
	void(*mthd_vrfysess_d0_free)(void* obj);
	int(*mthd_d0_sign)(void *keyobj, void *sessobj, void *sigobj,
		const unsigned char *msg, int msglen);
	int(*mthd_d0_vrfy)(void *keyobj, void *sessobj,
		void *sigobj, const unsigned char *msg, int msglen);
};


/* All the scheme methods for Scheme_new() */
extern SchemeMethods ECDSA_Methods;


/* A structure to hold a scheme. */
typedef struct Scheme Scheme;
struct Scheme
{
	SchemeMethods*  imp;
};


/* A structure to hold key materials. */
typedef struct KeyPair KeyPair;
struct KeyPair
{
	Scheme* sch;
	int     sec;
	void*   obj;
};


/**
 * A structure to hold signature.
 * It is opaque since signature format differ from scheme to scheme.
 */
typedef struct Signature Signature;
struct Signature
{
	Scheme*	sch;
	void*   obj;
};


/**
* Allocate for scheme.
*
* \param methods   Which scheme? Use pre-defined SchemeMethods here.
*
* \return  The pointer if succeeded, or NULL if failed.
*
* \note    Remember to free it with Scheme_free().
*/
Scheme *Scheme_new(SchemeMethods *methods);


/**
* Free a scheme.
*
* \param sch   Scheme object to free.
*/
void Scheme_free(Scheme *sch);


/**
* Allocate for a key pair.
*
* \param sch   A scheme object.
* \param sec   Security parameter.
*
* \return  An empty KeyPair object if OK, or NULL if error.
*
* \note    Remember to free it with KeyPair_free().
*/
KeyPair *KeyPair_new(Scheme *sch, int sec);


/**
* Generate a key pair.
*
* \param keypair   A KeyPair object.
*
* \return  0(OK), or <0(error).
*/
int KeyPair_gen(KeyPair *keypair);


/**
* Free a key pair.
*
* \param keypair   Keypair to free.
*/
void KeyPair_free(KeyPair *keypair);


/**
* Allocate for a signature structure used to store a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A signature object if OK, or NULL if error.
*/
Signature *Signature_new(KeyPair *keypair, Scheme *sch);


/**
* Get how many bytes are needed to encode this signature.
*
* Use this to prepare a buffer long enough, then call Signature_encode().
*
* \param sig   Signature object.
*
* \return  >=0 indicating the length , or <0 if error.
*/
int Signature_get_length(Signature *sig);


/**
* Encode a signature to bytes.
*
* \param sig   Signature object to encode.
* \param buf   Encoded signature goes here. Make sure it's long enough.
*
* \return  0(OK), or <0(error).
*/
int Signature_encode(Signature *sig, unsigned char *buf);


/**
* Free a signature object.
*
* \param sig   object to free.
*/
void Signature_free(Signature *sig);


/**
* Get printable name of the scheme.
*
* \param sch   A scheme object.
*
* \return  A read-only string.
*/
const unsigned char *Scheme_get_name(Scheme *sch);


/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct SignSessionD3 SignSessionD3;
struct SignSessionD3
{
	Scheme* sch;
	void*   obj;
};


/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct VrfySessionD3 VrfySessionD3;
struct VrfySessionD3
{
	Scheme* sch;
	void*   obj;
};


/**
* Allocate for a context used to generate a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD3 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD3_free().
*/
SignSessionD3 *SignSessionD3_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void SignSessionD3_free(SignSessionD3 *sess);


/**
* Allocate for a context used to verify a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD3 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD3_free().
*/
VrfySessionD3 *VrfySessionD3_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void VrfySessionD3_free(VrfySessionD3 *sess);


/**
* Run offline phase.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Offline part of signature (if exists) goes here.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D3_sign_offline(Scheme *sch, KeyPair *keypair,
	SignSessionD3 *sess, Signature *sig);


/**
* Run online phase.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Online part of signature (if exists) goes here.
* \param msg       Message to be signed.
* \param msglen    Length of message. Ensure it's larger than bitlen_rec.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D3_sign_online(Scheme *sch, KeyPair *keypair,
	SignSessionD3 *sess, Signature *sig,
	const unsigned char *msg, int msglen);


/**
* Run offline phase of verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
* \param sig		A signature object, possibly containing offline signature.
* \param msg		The message to be signed.
* \param msglen	Length of message in byte.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D3_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySessionD3 *sess,
	Signature *sig, const unsigned char *msg, int msglen);


/**
* Run online phase of verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
* \param sig       A signature to be verified.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D3_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySessionD3 *sess,
	Signature *sig);


/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct SignSessionD2 SignSessionD2;
struct SignSessionD2
{
	Scheme* sch;
	void*   obj;
};


/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct VrfySessionD2 VrfySessionD2;
struct VrfySessionD2
{
	Scheme* sch;
	void*   obj;
};


/**
* Allocate for a context used to generate a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD2 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD2_free().
*/
SignSessionD2 *SignSessionD2_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void SignSessionD2_free(SignSessionD2 *sess);


/**
* Allocate for a context used to verify a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD2 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD2_free().
*/
VrfySessionD2 *VrfySessionD2_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void VrfySessionD2_free(VrfySessionD2 *sess);


/**
* Run offline phase.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Offline part of signature (if exists) goes here.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D2_sign_offline(Scheme *sch, KeyPair *keypair,
	SignSessionD2 *sess, Signature *sig);


/**
* Run online phase.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Online part of signature (if exists) goes here.
* \param msg       Message to be signed.
* \param msglen    Length of message. Ensure it's larger than bitlen_rec.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D2_sign_online(Scheme *sch, KeyPair *keypair,
	SignSessionD2 *sess, Signature *sig,
	const unsigned char *msg, int msglen);


/**
* Run offline phase of verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
* \param sig		A signature object, possibly containing offline signature.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D2_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySessionD2 *sess,
	Signature *sig);


/**
* Run online phase of verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
* \param sig       A signature to be verified.
* \param msg		The message to be signed.
* \param msglen	   Length of message in byte.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D2_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySessionD2 *sess,
	Signature *sig, const unsigned char *msg, int msglen);







/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct SignSessionD1 SignSessionD1;
struct SignSessionD1
{
	Scheme* sch;
	void*   obj;
};


/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct VrfySessionD1 VrfySessionD1;
struct VrfySessionD1
{
	Scheme* sch;
	void*   obj;
};


/**
* Allocate for a context used to generate a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD1 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD1_free().
*/
SignSessionD1 *SignSessionD1_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void SignSessionD1_free(SignSessionD1 *sess);


/**
* Allocate for a context used to verify a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD1 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD1_free().
*/
VrfySessionD1 *VrfySessionD1_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void VrfySessionD1_free(VrfySessionD1 *sess);


/**
* Run offline phase.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Offline part of signature (if exists) goes here.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D1_sign_offline(Scheme *sch, KeyPair *keypair,
	SignSessionD1 *sess, Signature *sig);


/**
* Run online phase.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Online part of signature (if exists) goes here.
* \param msg       Message to be signed.
* \param msglen    Length of message. Ensure it's larger than bitlen_rec.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D1_sign_online(Scheme *sch, KeyPair *keypair,
	SignSessionD1 *sess, Signature *sig,
	const unsigned char *msg, int msglen);


/**
* Run offline phase of verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D1_vrfy_offline(Scheme *sch, KeyPair *keypair, VrfySessionD1 *sess);


/**
* Run online phase of verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
* \param sig       A signature to be verified.
* \param msg       The message to be signed.
* \param msglen	   Length of message in byte.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D1_vrfy_online(Scheme *sch, KeyPair *keypair, VrfySessionD1 *sess,
	Signature *sig, const unsigned char *msg, int msglen);











/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct SignSessionD0 SignSessionD0;
struct SignSessionD0
{
	Scheme* sch;
	void*   obj;
};


/**
* A structure to hold intermediate values used in a signing session.
* It is opaque, since the processes differ from scheme to scheme.
*/
typedef struct VrfySessionD0 VrfySessionD0;
struct VrfySessionD0
{
	Scheme* sch;
	void*   obj;
};


/**
* Allocate for a context used to generate a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD0 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD0_free().
*/
SignSessionD0 *SignSessionD0_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void SignSessionD0_free(SignSessionD0 *sess);


/**
* Allocate for a context used to verify a signature.
*
* \param keypair       A KeyPair object.
* \param sch           A scheme object.
*
* \return  A context object if OK, or NULL if error.
*
* \note    Once allocated, a SignSessionD0 object
*          can be used for many more times,
*          as long as it works with unchanged parameters.
*
* \note    Remember to free it by calling SignSessionD0_free().
*/
VrfySessionD0 *VrfySessionD0_new(KeyPair *keypair, Scheme *sch);


/**
* Free a session context object.
*
* \param sess  object to free.
*/
void VrfySessionD0_free(VrfySessionD0 *sess);


/**
* D0 signing.
*
* \param sch       A Scheme object.
* \param keypair   Key-pair used to sign.
* \param sess      Context for this signing session.
* \param sig       Offline part of signature (if exists) goes here.
* \param msg       The message to be signed.
* \param msglen	   Length of message in byte.
*
* \return  0(OK), or -1(failed).
*/
int Scheme_D0_sign(Scheme *sch, KeyPair *keypair,
	SignSessionD0 *sess, Signature *sig, const unsigned char *msg, int msglen);


/**
* D0 verification.
*
* \param sch       A scheme object.
* \param keypair   A key-pair used to verify the signature.
* \param sess      Context for this verifying session.
* \param sig       A signature object, possibly containing offline signature.
* \param msg       The message to be signed.
* \param msglen	   Length of message in byte.
*
* \return  0(accept), or 1(reject), or <0(error).
*/
int Scheme_D0_vrfy(Scheme *sch, KeyPair *keypair, VrfySessionD0 *sess,
	Signature *sig, const unsigned char *msg, int msglen);


#endif
