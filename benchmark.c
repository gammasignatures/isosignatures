/**
 * \file benchmark.c
 */
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
//#include <sys/times.h>
#include "scheme.h"
#include "benchmark.h"

static struct timeval tm1;
static struct timeval tm2;
void timerstart(){gettimeofday(&tm1, NULL);}
void timerstop(){gettimeofday(&tm2, NULL);}
int getms(){
    unsigned long long t = 1000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec) / 1000;
    return t;
}
unsigned long long getus(){
    unsigned long long t = 1000000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec);
    return t;
}


int testDeploy3OneUser(int sign_count, Scheme* sch,
        int bitlen_sec,
        int bitlen_msg,
        clock_t *s_tot, clock_t *son_tot,
        clock_t *v_tot, clock_t *von_tot)
{
    int ret;
    clock_t c0,c1,c2,c3,c4,c5,c6,c7;
    uint32_t soff=0,son=0,voff=0,von=0;

    KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
    assert(keypair != NULL);

    ret = KeyPair_gen(keypair);
    assert(ret == 0);

    int warming=1;
    for (++sign_count;sign_count>0;sign_count--){
        SignSessionD3 *signsess = SignSessionD3_new(keypair, sch);
        assert(signsess != NULL);

        VrfySessionD3 *vrfysess = VrfySessionD3_new(keypair, sch);
        assert(vrfysess != NULL);

        Signature *sig = Signature_new(keypair, sch);
        assert(sig != NULL);

        int msglen = bitlen_msg/8;
        unsigned char *msg = malloc(msglen);
        assert(msg != NULL);

        c0 = clock();
//        timerstart();
        ret = Scheme_D3_sign_offline(sch, keypair, signsess, sig);
//        timerstop();soff=getus();
        c1 = clock();soff=c1-c0;;

        assert(ret >= 0);

        c2 = clock();
//        timerstart();
        ret = Scheme_D3_sign_online(sch, keypair, signsess, sig, msg, msglen);
//        timerstop();son=getus();
        c3 = clock();son=c3-c2;

        assert(ret >= 0);

        c4 = clock();
//        timerstart();
        ret = Scheme_D3_vrfy_offline(sch, keypair, vrfysess, sig, msg, msglen);
//        timerstop();voff=getus();
        c5 = clock();voff=c5-c4;

        if (ret < 0) return -1;//assert(ret >= 0);

        c6 = clock();
//        timerstart();
        ret = Scheme_D3_vrfy_online(sch, keypair, vrfysess, sig);
//        timerstop();von=getus();
        c7 = clock();von=c7-c6;

        if (ret < 0) return -1;//assert(ret >= 0);

    end:

        if (warming)
            warming=0;
        else
        {
            if (s_tot) *s_tot += son+soff;
            if (son_tot) *son_tot += son;
            if (von_tot) *von_tot += von;
            if (v_tot) *v_tot += von+voff;
        }

        SignSessionD3_free(signsess);
        VrfySessionD3_free(vrfysess);
        Signature_free(sig);
        free(msg);
    }

    KeyPair_free(keypair);
    return 0;
}


int testDeploy2OneUser(int sign_count, Scheme* sch,
	int bitlen_sec,
	int bitlen_msg,
	clock_t *s_tot, clock_t *son_tot,
	clock_t *v_tot, clock_t *von_tot)
{
	int ret;
	clock_t c0, c1, c2, c3, c4, c5, c6, c7;
	uint32_t soff = 0, son = 0, voff = 0, von = 0;

	KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
	assert(keypair != NULL);

	ret = KeyPair_gen(keypair);
	assert(ret == 0);

	int warming = 1;
	for (++sign_count;sign_count>0;sign_count--) {
		SignSessionD2 *signsess = SignSessionD2_new(keypair, sch);
		assert(signsess != NULL);

		VrfySessionD2 *vrfysess = VrfySessionD2_new(keypair, sch);
		assert(vrfysess != NULL);

		Signature *sig = Signature_new(keypair, sch);
		assert(sig != NULL);

		int msglen = bitlen_msg / 8;
		unsigned char *msg = malloc(msglen);
		assert(msg != NULL);

		c0 = clock();
		//        timerstart();
		ret = Scheme_D2_sign_offline(sch, keypair, signsess, sig);
		//        timerstop();soff=getus();
		c1 = clock();soff = c1 - c0;;

		assert(ret >= 0);

		c2 = clock();
		//        timerstart();
		ret = Scheme_D2_sign_online(sch, keypair, signsess, sig, msg, msglen);
		//        timerstop();son=getus();
		c3 = clock();son = c3 - c2;

		assert(ret >= 0);

		c4 = clock();
		//        timerstart();
		ret = Scheme_D2_vrfy_offline(sch, keypair, vrfysess, sig);
		//        timerstop();voff=getus();
		c5 = clock();voff = c5 - c4;

		if (ret < 0) return -1;//assert(ret >= 0);

		c6 = clock();
		//        timerstart();
		ret = Scheme_D2_vrfy_online(sch, keypair, vrfysess, sig, msg , msglen);
		//        timerstop();von=getus();
		c7 = clock();von = c7 - c6;

		if (ret < 0) return -1;//assert(ret >= 0);

	end:

		if (warming)
			warming = 0;
		else
		{
			if (s_tot) *s_tot += son + soff;
			if (son_tot) *son_tot += son;
			if (von_tot) *von_tot += von;
			if (v_tot) *v_tot += von + voff;
		}

		SignSessionD2_free(signsess);
		VrfySessionD2_free(vrfysess);
		Signature_free(sig);
		free(msg);
	}

	KeyPair_free(keypair);
	return 0;
}


int testDeploy1OneUser(int sign_count, Scheme* sch,
	int bitlen_sec,
	int bitlen_msg,
	clock_t *s_tot, clock_t *son_tot,
	clock_t *v_tot, clock_t *von_tot)
{
	int ret;
	clock_t c0, c1, c2, c3, c4, c5, c6, c7;
	uint32_t soff = 0, son = 0, voff = 0, von = 0;

	KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
	assert(keypair != NULL);

	ret = KeyPair_gen(keypair);
	assert(ret == 0);

	int warming = 1;
	for (++sign_count;sign_count>0;sign_count--) {
		SignSessionD1 *signsess = SignSessionD1_new(keypair, sch);
		assert(signsess != NULL);

		VrfySessionD1 *vrfysess = VrfySessionD1_new(keypair, sch);
		assert(vrfysess != NULL);

		Signature *sig = Signature_new(keypair, sch);
		assert(sig != NULL);

		int msglen = bitlen_msg / 8;
		unsigned char *msg = malloc(msglen);
		assert(msg != NULL);

		c0 = clock();
		//        timerstart();
		ret = Scheme_D1_sign_offline(sch, keypair, signsess, sig);
		//        timerstop();soff=getus();
		c1 = clock();soff = c1 - c0;;

		assert(ret >= 0);

		c2 = clock();
		//        timerstart();
		ret = Scheme_D1_sign_online(sch, keypair, signsess, sig, msg, msglen);
		//        timerstop();son=getus();
		c3 = clock();son = c3 - c2;

		assert(ret >= 0);

		c4 = clock();
		//        timerstart();
		ret = Scheme_D1_vrfy_offline(sch, keypair, vrfysess);
		//        timerstop();voff=getus();
		c5 = clock();voff = c5 - c4;

		if (ret < 0) return -1;//assert(ret >= 0);

		c6 = clock();
		//        timerstart();
		ret = Scheme_D1_vrfy_online(sch, keypair, vrfysess, sig, msg, msglen);
		//        timerstop();von=getus();
		c7 = clock();von = c7 - c6;

		if (ret < 0) return -1;//assert(ret >= 0);

	end:

		if (warming)
			warming = 0;
		else
		{
			if (s_tot) *s_tot += son + soff;
			if (son_tot) *son_tot += son;
			if (von_tot) *von_tot += von;
			if (v_tot) *v_tot += von + voff;
		}

		SignSessionD1_free(signsess);
		VrfySessionD1_free(vrfysess);
		Signature_free(sig);
		free(msg);
	}

	KeyPair_free(keypair);
	return 0;
}


int testDeploy0OneUser(int sign_count, Scheme* sch,
	int bitlen_sec,
	int bitlen_msg,
	clock_t *s_tot, clock_t *v_tot)
{
	int ret;
	clock_t c0, c1, c2, c3, c4, c5, c6, c7;
	uint32_t soff = 0, son = 0, voff = 0, von = 0;

	KeyPair *keypair = KeyPair_new(sch, bitlen_sec);
	assert(keypair != NULL);

	ret = KeyPair_gen(keypair);
	assert(ret == 0);

	int warming = 1;
	for (++sign_count;sign_count>0;sign_count--) {
		SignSessionD0 *signsess = SignSessionD0_new(keypair, sch);
		assert(signsess != NULL);

		VrfySessionD0 *vrfysess = VrfySessionD0_new(keypair, sch);
		assert(vrfysess != NULL);

		Signature *sig = Signature_new(keypair, sch);
		assert(sig != NULL);

		int msglen = bitlen_msg / 8;
		unsigned char *msg = malloc(msglen);
		assert(msg != NULL);

		c0 = clock();
		//        timerstart();
		ret = Scheme_D0_sign(sch, keypair, signsess, sig, msg, msglen);
		//        timerstop();soff=getus();
		c1 = clock();soff = c1 - c0;;

		assert(ret >= 0);

		c6 = clock();
		//        timerstart();
		ret = Scheme_D0_vrfy(sch, keypair, vrfysess, sig, msg, msglen);
		//        timerstop();von=getus();
		c7 = clock();von = c7 - c6;

		if (ret < 0) return -1;//assert(ret >= 0);

	end:

		if (warming)
			warming = 0;
		else
		{
			if (s_tot) *s_tot += son + soff;
			if (v_tot) *v_tot += von + voff;
		}

		SignSessionD0_free(signsess);
		VrfySessionD0_free(vrfysess);
		Signature_free(sig);
		free(msg);
	}

	KeyPair_free(keypair);
	return 0;
}



static Scheme * get_scheme_by_id(int schid)
{
    Scheme *sch = NULL;
    switch (schid)
    {
	case SCHID_EC_KCDSA:
		sch = Scheme_new(&ECKCDSA_Methods);
	case SCHID_EC_DSA:
	default:
		sch = Scheme_new(&ECDSA_Methods);
    }
    return sch;
}


int testDeploy3(int verbose, int schid, int bitlen_sec,
		int bitlen_msg,
		int sign_count, int user_count,
		clock_t *ret_sign_tot, clock_t *ret_sign_onl,
		clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    int ret;

    int i;
    clock_t sign_total = 0;
    clock_t sign_online_total = 0;
    clock_t vrfy_total = 0;
    clock_t vrfy_online_total = 0;

    /* Warm up */
    ret = testDeploy3OneUser(sign_count, sch,
            bitlen_sec,
            bitlen_msg,
            &sign_total, &sign_online_total,
            &vrfy_total, &vrfy_online_total);

    assert(ret >= 0);

    sign_total = 0;
    sign_online_total = 0;
    vrfy_total = 0;
    vrfy_online_total = 0;
    
    int VB=8;
    for (i=1; i<=user_count; i++)
    {
        testDeploy3OneUser(sign_count, sch,
                bitlen_sec,
                bitlen_msg,
                &sign_total, &sign_online_total,
                &vrfy_total, &vrfy_online_total);
    }

    *ret_sign_tot = sign_total;
    *ret_sign_onl = sign_online_total;
    *ret_vrfy_tot = vrfy_total;
    *ret_vrfy_onl = vrfy_online_total;

    free(sch);
    return 0;
}


const char* getnamebyschid(int schid)
{
    Scheme* sch=get_scheme_by_id(schid);
    const char* ret=Scheme_get_name(sch);
    Scheme_free(sch);
    return ret;
}


int testDeploy2(int verbose, int schid, int bitlen_sec,
		int bitlen_msg,
		int sign_count, int user_count,
		clock_t *ret_sign_tot, clock_t *ret_sign_onl,
		clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
	Scheme *sch = get_scheme_by_id(schid);
	if (sch == NULL) return -1;

	int ret;

	int i;
	clock_t sign_total = 0;
	clock_t sign_online_total = 0;
	clock_t vrfy_total = 0;
	clock_t vrfy_online_total = 0;

	/* Warm up */
	ret = testDeploy2OneUser(sign_count, sch,
		bitlen_sec,
		bitlen_msg,
		&sign_total, &sign_online_total,
		&vrfy_total, &vrfy_online_total);

	assert(ret >= 0);

	sign_total = 0;
	sign_online_total = 0;
	vrfy_total = 0;
	vrfy_online_total = 0;

	int VB = 8;
	for (i = 1; i <= user_count; i++)
	{
		testDeploy2OneUser(sign_count, sch,
			bitlen_sec,
			bitlen_msg,
			&sign_total, &sign_online_total,
			&vrfy_total, &vrfy_online_total);
	}

	*ret_sign_tot = sign_total;
	*ret_sign_onl = sign_online_total;
	*ret_vrfy_tot = vrfy_total;
	*ret_vrfy_onl = vrfy_online_total;

	free(sch);
	return 0;
}


int testDeploy1(int verbose, int schid, int bitlen_sec,
	int bitlen_msg,
	int sign_count, int user_count,
	clock_t *ret_sign_tot, clock_t *ret_sign_onl,
	clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
	Scheme *sch = get_scheme_by_id(schid);
	if (sch == NULL) return -1;

	int ret;

	int i;
	clock_t sign_total = 0;
	clock_t sign_online_total = 0;
	clock_t vrfy_total = 0;
	clock_t vrfy_online_total = 0;

	/* Warm up */
	ret = testDeploy1OneUser(sign_count, sch,
		bitlen_sec,
		bitlen_msg,
		&sign_total, &sign_online_total,
		&vrfy_total, &vrfy_online_total);

	assert(ret >= 0);

	sign_total = 0;
	sign_online_total = 0;
	vrfy_total = 0;
	vrfy_online_total = 0;

	int VB = 8;
	for (i = 1; i <= user_count; i++)
	{
		testDeploy1OneUser(sign_count, sch,
			bitlen_sec,
			bitlen_msg,
			&sign_total, &sign_online_total,
			&vrfy_total, &vrfy_online_total);
	}

	*ret_sign_tot = sign_total;
	*ret_sign_onl = sign_online_total;
	*ret_vrfy_tot = vrfy_total;
	*ret_vrfy_onl = vrfy_online_total;

	free(sch);
	return 0;
}


int testDeploy0(int verbose, int schid, int bitlen_sec,
	int bitlen_msg,
	int sign_count, int user_count,
	clock_t *ret_sign, clock_t *ret_vrfy)
{
	Scheme *sch = get_scheme_by_id(schid);
	if (sch == NULL) return -1;

	int ret;

	int i;
	clock_t sign_total = 0;
	clock_t vrfy_total = 0;

	/* Warm up */
	ret = testDeploy0OneUser(sign_count, sch,
		bitlen_sec,
		bitlen_msg,
		&sign_total, &vrfy_total);

	assert(ret >= 0);

	sign_total = 0;
	vrfy_total = 0;

	int VB = 8;
	for (i = 1; i <= user_count; i++)
	{
		testDeploy0OneUser(sign_count, sch,
			bitlen_sec,
			bitlen_msg,
			&sign_total, &vrfy_total);
	}

	*ret_sign = sign_total;
	*ret_vrfy = vrfy_total;

	free(sch);
	return 0;
}
