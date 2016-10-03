/**
 * \file benchmark.h
 */

#ifndef __BENCHMARK_H__
#define __BENCHMARK_H__


#include <time.h>

/* Scheme IDs in this project. */
#define SCHID_OMG       0x000000
#define SCHID_ECOMG0    0x0e0000  // No covering
#define SCHID_ECOMG1    0x0e0001  // XOR covering
#define SCHID_ECOMG2    0x0e0002  // AES covering
#define SCHID_AO        0x000100
#define SCHID_ECAO      0x0e0100
#define SCHID_PV        0x000200
#define SCHID_ECPV0     0x0e0200  // XOR covering
#define SCHID_ECPV1     0x0e0201  // AES covering


#define SCHID_EC_DSA	    0x100000
#define SCHID_EC_RDSA	    0x200000
#define SCHID_EC_GDSA	    0x300000
#define SCHID_EC_KCDSA	    0x400000
#define SCHID_EC_SCHNORR	0x500000
#define SCHID_EC_SM2	    0x600000
#define SCHID_EC_CDSA_I	    0x700000
#define SCHID_EC_CDSA_II	0x800000


/**
 * Select a scheme, specify params, and run the scheme in Deployment 3.
 * 
 * In Deployment 3, verifier knows msg and d before its offline phase.
 *
 * \param verbose       Whether to enable verbose mode.
 * \param schid         Which scheme? Use SCHID_* here.
 * \param bitlen_sec    Security parameter. Use SEC_* here.
 * \param bitlen_msg    Message length.
 * \param sign_count    How many signatures to generate for one signer.
 * \param user_count    How many signers.
 *
 * \param ret_sign_tot  Total signing time will go here.
 * \param ret_sign_onl  Online signing time will go here.
 * \param ret_vrfy_tot  Total vrfying time will go here.
 * \param ret_vrfy_onl  Online vrfying time will go here.
 *
 * \return  0(OK), or -1(failed).
 */
int testDeploy3(int verbose, int schid, int bitlen_sec,
		int bitlen_msg,
		int sign_count, int user_count,
		clock_t *ret_sign_tot, clock_t *ret_sign_onl,
		clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl);


/**
* Select a scheme, specify params, and run the scheme in Deployment 2.
*
* In Deployment 2, verifier knows d before its offline phase.
*
* \param verbose       Whether to enable verbose mode.
* \param schid         Which scheme? Use SCHID_* here.
* \param bitlen_sec    Security parameter. Use SEC_* here.
* \param bitlen_msg    Message length.
* \param sign_count    How many signatures to generate for one signer.
* \param user_count    How many signers.
*
* \param ret_sign_tot  Total signing time will go here.
* \param ret_sign_onl  Online signing time will go here.
* \param ret_vrfy_tot  Total vrfying time will go here.
* \param ret_vrfy_onl  Online vrfying time will go here.
*
* \return  0(OK), or -1(failed).
*/
int testDeploy2(int verbose, int schid, int bitlen_sec,
		int bitlen_msg,
		int sign_count, int user_count,
		clock_t *ret_sign_tot, clock_t *ret_sign_onl,
		clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl);


/**
* Select a scheme, specify params, and run the scheme in Deployment 1.
*
* In Deployment 1, verifier knows nothing before its offline phase.
*
* \param verbose       Whether to enable verbose mode.
* \param schid         Which scheme? Use SCHID_* here.
* \param bitlen_sec    Security parameter. Use SEC_* here.
* \param bitlen_msg    Message length.
* \param sign_count    How many signatures to generate for one signer.
* \param user_count    How many signers.
*
* \param ret_sign_tot  Total signing time will go here.
* \param ret_sign_onl  Online signing time will go here.
* \param ret_vrfy_tot  Total vrfying time will go here.
* \param ret_vrfy_onl  Online vrfying time will go here.
*
* \return  0(OK), or -1(failed).
*/
int testDeploy1(int verbose, int schid, int bitlen_sec,
	int bitlen_msg,
	int sign_count, int user_count,
	clock_t *ret_sign_tot, clock_t *ret_sign_onl,
	clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl);


/**
* Select a scheme, specify params, and run the scheme in Deployment 0.
*
* Deployment 0 means the completely online mode.
*
* \param verbose       Whether to enable verbose mode.
* \param schid         Which scheme? Use SCHID_* here.
* \param bitlen_sec    Security parameter. Use SEC_* here.
* \param bitlen_msg    Message length.
* \param sign_count    How many signatures to generate for one signer.
* \param user_count    How many signers.
*
* \param ret_sign      Signing time will go here.
* \param ret_vrfy      Vrfying time will go here.
*
* \return  0(OK), or -1(failed).
*/
int testDeploy0(int verbose, int schid, int bitlen_sec,
	int bitlen_msg,
	int sign_count, int user_count,
	clock_t *ret_sign, clock_t *ret_vrfy);


const char* getnamebyschid(int schid);

#endif
