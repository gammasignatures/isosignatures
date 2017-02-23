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


int testD3OneUser(int sign_count, Scheme* sch,
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
        SignSessionD3 *signsess = SignSessionD3_new(keypair, sch);
        assert(signsess != NULL);

        VrfySessionD3 *vrfysess = VrfySessionD3_new(keypair, sch);
        assert(vrfysess != NULL);

        Signature *sig = Signature_new(keypair, sch);
        assert(sig != NULL);

        int msglen = bitlen_msg / 8;
        unsigned char *msg = malloc(msglen);
        assert(msg != NULL);

        c0 = clock();
        //        timerstart();
        ret = Scheme_D3_sign_offline(sch, keypair, signsess, sig);
        //        timerstop();soff=getus();
        c1 = clock();soff = c1 - c0;;

        assert(ret >= 0);

        c2 = clock();
        //        timerstart();
        ret = Scheme_D3_sign_online(sch, keypair, signsess, sig, msg, msglen);
        //        timerstop();son=getus();
        c3 = clock();son = c3 - c2;

        assert(ret >= 0);

        c4 = clock();
        //        timerstart();
        ret = Scheme_D3_vrfy_offline(sch, keypair, vrfysess, sig, msg, msglen);
        //        timerstop();voff=getus();
        c5 = clock();voff = c5 - c4;

        if (ret < 0) return -1;//assert(ret >= 0);

        c6 = clock();
        //        timerstart();
        ret = Scheme_D3_vrfy_online(sch, keypair, vrfysess, sig);
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

        SignSessionD3_free(signsess);
        VrfySessionD3_free(vrfysess);
        Signature_free(sig);
        free(msg);
    }

    KeyPair_free(keypair);
    return 0;
}


int testD3bOneUser(int sign_count, Scheme* sch,
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
        SignSessionD3b *signsess = SignSessionD3b_new(keypair, sch);
        assert(signsess != NULL);

        VrfySessionD3b *vrfysess = VrfySessionD3b_new(keypair, sch);
        assert(vrfysess != NULL);

        Signature *sig = Signature_new(keypair, sch);
        assert(sig != NULL);

        int msglen = bitlen_msg / 8;
        unsigned char *msg = malloc(msglen);
        assert(msg != NULL);

        c0 = clock();
        //        timerstart();
        ret = Scheme_D3b_sign_offline(sch, keypair, signsess, sig);
        //        timerstop();soff=getus();
        c1 = clock();soff = c1 - c0;;

        assert(ret >= 0);

        c2 = clock();
        //        timerstart();
        ret = Scheme_D3b_sign_online(sch, keypair, signsess, sig, msg, msglen);
        //        timerstop();son=getus();
        c3 = clock();son = c3 - c2;

        assert(ret >= 0);

        c4 = clock();
        //        timerstart();
        ret = Scheme_D3b_vrfy_offline(sch, keypair, vrfysess, sig, msg, msglen);
        //        timerstop();voff=getus();
        c5 = clock();voff = c5 - c4;

        if (ret < 0) return -1;//assert(ret >= 0);

        c6 = clock();
        //        timerstart();
        ret = Scheme_D3b_vrfy_online(sch, keypair, vrfysess, sig);
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

        SignSessionD3b_free(signsess);
        VrfySessionD3b_free(vrfysess);
        Signature_free(sig);
        free(msg);
    }

    KeyPair_free(keypair);
    return 0;
}


int testD2OneUser(int sign_count, Scheme* sch,
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
        ret = Scheme_D2_vrfy_online(sch, keypair, vrfysess, sig, msg, msglen);
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


int testD2bOneUser(int sign_count, Scheme* sch,
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
        SignSessionD2b *signsess = SignSessionD2b_new(keypair, sch);
        assert(signsess != NULL);

        VrfySessionD2b *vrfysess = VrfySessionD2b_new(keypair, sch);
        assert(vrfysess != NULL);

        Signature *sig = Signature_new(keypair, sch);
        assert(sig != NULL);

        int msglen = bitlen_msg / 8;
        unsigned char *msg = malloc(msglen);
        assert(msg != NULL);

        c0 = clock();
        //        timerstart();
        ret = Scheme_D2b_sign_offline(sch, keypair, signsess, sig);
        //        timerstop();soff=getus();
        c1 = clock();soff = c1 - c0;;

        assert(ret >= 0);

        c2 = clock();
        //        timerstart();
        ret = Scheme_D2b_sign_online(sch, keypair, signsess, sig, msg, msglen);
        //        timerstop();son=getus();
        c3 = clock();son = c3 - c2;

        assert(ret >= 0);

        c4 = clock();
        //        timerstart();
        ret = Scheme_D2b_vrfy_offline(sch, keypair, vrfysess, sig);
        //        timerstop();voff=getus();
        c5 = clock();voff = c5 - c4;

        if (ret < 0) return -1;//assert(ret >= 0);

        c6 = clock();
        //        timerstart();
        ret = Scheme_D2b_vrfy_online(sch, keypair, vrfysess, sig, msg, msglen);
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

        SignSessionD2b_free(signsess);
        VrfySessionD2b_free(vrfysess);
        Signature_free(sig);
        free(msg);
    }

    KeyPair_free(keypair);
    return 0;
}


int testD1OneUser(int sign_count, Scheme* sch,
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


int testD0OneUser(int sign_count, Scheme* sch,
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

		assert(ret >= 0);

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
    case SCHID_EC_RDSA:
        sch = Scheme_new(&ECRDSA_Methods);
        break;
    case SCHID_EC_CDSA_I:
        sch = Scheme_new(&ECCDSA1_Methods);
        break;
    case SCHID_EC_CDSA_II:
        sch = Scheme_new(&ECCDSA2_Methods);
        break;
    case SCHID_EC_KCDSA:
        sch = Scheme_new(&ECKCDSA_Methods);
        break;
    case SCHID_EC_SCHNORR:
        sch = Scheme_new(&ECSNOR_Methods);
        break;
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
    int measured_sign_off;
    int measured_sign_on;
    int measured_vrfy_off;
    int measured_vrfy_on;
    int ret, i, j;
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    /* Warm up */
    ret = testD3OneUser(1, sch, bitlen_sec, bitlen_msg,
        NULL, NULL, NULL, NULL);

    assert(ret >= 0);

    KeyPair **keypair = calloc(user_count, sizeof(KeyPair*));
    for (i = 0;i < user_count;++i)
    {
        keypair[i] = KeyPair_new(sch, bitlen_sec);
        assert(keypair[i] != NULL);
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    SignSessionD3 ***signsess = calloc(user_count, sizeof(SignSessionD3**));
    for (i = 0;i < user_count;++i)
    {
        signsess[i] = calloc(sign_count, sizeof(SignSessionD3*));
        assert(signsess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            signsess[i][j] = SignSessionD3_new(keypair[i], sch);
            assert(signsess[i][j] != NULL);
        }
    }
    VrfySessionD3 ***vrfysess = calloc(user_count, sizeof(VrfySessionD3**));
    for (i = 0;i < user_count;++i)
    {
        vrfysess[i] = calloc(sign_count, sizeof(VrfySessionD3*));
        assert(vrfysess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            vrfysess[i][j] = VrfySessionD3_new(keypair[i], sch);
            assert(vrfysess[i][j] != NULL);
        }
    }
    Signature ***sig = calloc(user_count, sizeof(Signature**));
    for (i = 0;i < user_count;++i)
    {
        sig[i] = calloc(sign_count, sizeof(Signature*));
        assert(sig[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            sig[i][j] = Signature_new(keypair[i], sch);
            assert(sig[i][j] != NULL);
        }
    }

    int msglen = bitlen_msg / 8;
    unsigned char *msg = malloc(msglen);
    assert(msg != NULL);

    /* Gen all keys */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    timerstop();

    /* Do all Signs-offline */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D3_sign_offline(sch, keypair[i], signsess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_off = getms();

    /* Do all Signs-online */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D3_sign_online(sch, keypair[i], signsess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_on = getms();

    /* Do all Verifys-offline */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D3_vrfy_offline(sch, keypair[i], vrfysess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_off = getms();

    /* Do all Verifys-online */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D3_vrfy_online(sch, keypair[i], vrfysess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_on = getms();

    if (ret_sign_tot != NULL) *ret_sign_tot = measured_sign_off + measured_sign_on;
    if (ret_sign_onl != NULL) *ret_sign_onl = measured_sign_on;
    if (ret_vrfy_tot != NULL) *ret_vrfy_tot = measured_vrfy_off + measured_vrfy_on;
    if (ret_vrfy_onl != NULL) *ret_vrfy_onl = measured_vrfy_on;

clean:
    free(sch);
    //A lot of things to clean
    return 0;
}


int testDeploy3b(int verbose, int schid, int bitlen_sec,
    int bitlen_msg,
    int sign_count, int user_count,
    clock_t *ret_sign_tot, clock_t *ret_sign_onl,
    clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
    int measured_sign_off;
    int measured_sign_on;
    int measured_vrfy_off;
    int measured_vrfy_on;
    int ret, i, j;
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    /* Warm up */
    ret = testD3bOneUser(1, sch, bitlen_sec, bitlen_msg,
        NULL, NULL, NULL, NULL);

    assert(ret >= 0);

    KeyPair **keypair = calloc(user_count, sizeof(KeyPair*));
    for (i = 0;i < user_count;++i)
    {
        keypair[i] = KeyPair_new(sch, bitlen_sec);
        assert(keypair[i] != NULL);
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    SignSessionD3b ***signsess = calloc(user_count, sizeof(SignSessionD3b**));
    for (i = 0;i < user_count;++i)
    {
        signsess[i] = calloc(sign_count, sizeof(SignSessionD3b*));
        assert(signsess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            signsess[i][j] = SignSessionD3b_new(keypair[i], sch);
            assert(signsess[i][j] != NULL);
        }
    }
    VrfySessionD3b ***vrfysess = calloc(user_count, sizeof(VrfySessionD3b**));
    for (i = 0;i < user_count;++i)
    {
        vrfysess[i] = calloc(sign_count, sizeof(VrfySessionD3b*));
        assert(vrfysess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            vrfysess[i][j] = VrfySessionD3b_new(keypair[i], sch);
            assert(vrfysess[i][j] != NULL);
        }
    }
    Signature ***sig = calloc(user_count, sizeof(Signature**));
    for (i = 0;i < user_count;++i)
    {
        sig[i] = calloc(sign_count, sizeof(Signature*));
        assert(sig[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            sig[i][j] = Signature_new(keypair[i], sch);
            assert(sig[i][j] != NULL);
        }
    }

    int msglen = bitlen_msg / 8;
    unsigned char *msg = malloc(msglen);
    assert(msg != NULL);

    /* Gen all keys */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    timerstop();

    /* Do all Signs-offline */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D3b_sign_offline(sch, keypair[i], signsess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_off = getms();

    /* Do all Signs-online */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D3b_sign_online(sch, keypair[i], signsess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_on = getms();

    /* Do all Verifys-offline */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D3b_vrfy_offline(sch, keypair[i], vrfysess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_off = getms();

    /* Do all Verifys-online */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D3b_vrfy_online(sch, keypair[i], vrfysess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_on = getms();

    if (ret_sign_tot != NULL) *ret_sign_tot = measured_sign_off + measured_sign_on;
    if (ret_sign_onl != NULL) *ret_sign_onl = measured_sign_on;
    if (ret_vrfy_tot != NULL) *ret_vrfy_tot = measured_vrfy_off + measured_vrfy_on;
    if (ret_vrfy_onl != NULL) *ret_vrfy_onl = measured_vrfy_on;

clean:
    free(sch);
    //A lot of things to clean
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
    int measured_sign_off;
    int measured_sign_on;
    int measured_vrfy_off;
    int measured_vrfy_on;
    int ret, i, j;
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    /* Warm up */
    ret = testD2OneUser(1, sch, bitlen_sec, bitlen_msg,
        NULL, NULL, NULL, NULL);

    assert(ret >= 0);

    KeyPair **keypair = calloc(user_count, sizeof(KeyPair*));
    for (i = 0;i < user_count;++i)
    {
        keypair[i] = KeyPair_new(sch, bitlen_sec);
        assert(keypair[i] != NULL);
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    SignSessionD2 ***signsess = calloc(user_count, sizeof(SignSessionD2**));
    for (i = 0;i < user_count;++i)
    {
        signsess[i] = calloc(sign_count, sizeof(SignSessionD2*));
        assert(signsess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            signsess[i][j] = SignSessionD2_new(keypair[i], sch);
            assert(signsess[i][j] != NULL);
        }
    }
    VrfySessionD2 ***vrfysess = calloc(user_count, sizeof(VrfySessionD2**));
    for (i = 0;i < user_count;++i)
    {
        vrfysess[i] = calloc(sign_count, sizeof(VrfySessionD2*));
        assert(vrfysess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            vrfysess[i][j] = VrfySessionD2_new(keypair[i], sch);
            assert(vrfysess[i][j] != NULL);
        }
    }
    Signature ***sig = calloc(user_count, sizeof(Signature**));
    for (i = 0;i < user_count;++i)
    {
        sig[i] = calloc(sign_count, sizeof(Signature*));
        assert(sig[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            sig[i][j] = Signature_new(keypair[i], sch);
            assert(sig[i][j] != NULL);
        }
    }

    int msglen = bitlen_msg / 8;
    unsigned char *msg = malloc(msglen);
    assert(msg != NULL);

    /* Gen all keys */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    timerstop();

    /* Do all Signs-offline */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D2_sign_offline(sch, keypair[i], signsess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_off = getms();

    /* Do all Signs-online */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D2_sign_online(sch, keypair[i], signsess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_on = getms();

    /* Do all Verifys-offline */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D2_vrfy_offline(sch, keypair[i], vrfysess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_off = getms();

    /* Do all Verifys-online */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D2_vrfy_online(sch, keypair[i], vrfysess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_on = getms();

    if (ret_sign_tot != NULL) *ret_sign_tot = measured_sign_off + measured_sign_on;
    if (ret_sign_onl != NULL) *ret_sign_onl = measured_sign_on;
    if (ret_vrfy_tot != NULL) *ret_vrfy_tot = measured_vrfy_off + measured_vrfy_on;
    if (ret_vrfy_onl != NULL) *ret_vrfy_onl = measured_vrfy_on;

clean:
    free(sch);
    //A lot of things to clean
    return 0;
}


int testDeploy2b(int verbose, int schid, int bitlen_sec,
    int bitlen_msg,
    int sign_count, int user_count,
    clock_t *ret_sign_tot, clock_t *ret_sign_onl,
    clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
    int measured_sign_off;
    int measured_sign_on;
    int measured_vrfy_off;
    int measured_vrfy_on;
    int ret, i, j;
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    /* Warm up */
    ret = testD2bOneUser(1, sch,
        bitlen_sec,
        bitlen_msg,
        NULL, NULL, NULL, NULL);

    assert(ret >= 0);

    KeyPair **keypair = calloc(user_count, sizeof(KeyPair*));
    for (i = 0;i < user_count;++i)
    {
        keypair[i] = KeyPair_new(sch, bitlen_sec);
        assert(keypair[i] != NULL);
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    SignSessionD2b ***signsess = calloc(user_count, sizeof(SignSessionD2b**));
    for (i = 0;i < user_count;++i)
    {
        signsess[i] = calloc(sign_count, sizeof(SignSessionD2b*));
        assert(signsess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            signsess[i][j] = SignSessionD2b_new(keypair[i], sch);
            assert(signsess[i][j] != NULL);
        }
    }
    VrfySessionD2b ***vrfysess = calloc(user_count, sizeof(VrfySessionD2b**));
    for (i = 0;i < user_count;++i)
    {
        vrfysess[i] = calloc(sign_count, sizeof(VrfySessionD2b*));
        assert(vrfysess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            vrfysess[i][j] = VrfySessionD2b_new(keypair[i], sch);
            assert(vrfysess[i][j] != NULL);
        }
    }
    Signature ***sig = calloc(user_count, sizeof(Signature**));
    for (i = 0;i < user_count;++i)
    {
        sig[i] = calloc(sign_count, sizeof(Signature*));
        assert(sig[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            sig[i][j] = Signature_new(keypair[i], sch);
            assert(sig[i][j] != NULL);
        }
    }

    int msglen = bitlen_msg / 8;
    unsigned char *msg = malloc(msglen);
    assert(msg != NULL);

    /* Gen all keys */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    timerstop();

    /* Do all Signs-offline */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D2b_sign_offline(sch, keypair[i], signsess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_off = getms();

    /* Do all Signs-online */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D2b_sign_online(sch, keypair[i], signsess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_on = getms();

    /* Do all Verifys-offline */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D2b_vrfy_offline(sch, keypair[i], vrfysess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_off = getms();

    /* Do all Verifys-online */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D2b_vrfy_online(sch, keypair[i], vrfysess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_on = getms();

    if (ret_sign_tot != NULL) *ret_sign_tot = measured_sign_off + measured_sign_on;
    if (ret_sign_onl != NULL) *ret_sign_onl = measured_sign_on;
    if (ret_vrfy_tot != NULL) *ret_vrfy_tot = measured_vrfy_off + measured_vrfy_on;
    if (ret_vrfy_onl != NULL) *ret_vrfy_onl = measured_vrfy_on;

clean:
    free(sch);
    //A lot of things to clean
    return 0;
}


int testDeploy1(int verbose, int schid, int bitlen_sec,
	int bitlen_msg,
	int sign_count, int user_count,
	clock_t *ret_sign_tot, clock_t *ret_sign_onl,
	clock_t *ret_vrfy_tot, clock_t *ret_vrfy_onl)
{
    int measured_sign_off;
    int measured_sign_on;
    int measured_vrfy_off;
    int measured_vrfy_on;
    int ret, i, j;
    Scheme *sch = get_scheme_by_id(schid);
    if (sch == NULL) return -1;

    /* Warm up */
    ret = testD1OneUser(1, sch,
        bitlen_sec,
        bitlen_msg,
        NULL, NULL, NULL, NULL);

    assert(ret >= 0);

    KeyPair **keypair = calloc(user_count, sizeof(KeyPair*));
    for (i = 0;i < user_count;++i)
    {
        keypair[i] = KeyPair_new(sch, bitlen_sec);
        assert(keypair[i] != NULL);
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    SignSessionD1 ***signsess = calloc(user_count, sizeof(SignSessionD1**));
    for (i = 0;i < user_count;++i)
    {
        signsess[i] = calloc(sign_count, sizeof(SignSessionD1*));
        assert(signsess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            signsess[i][j] = SignSessionD1_new(keypair[i], sch);
            assert(signsess[i][j] != NULL);
        }
    }
    VrfySessionD1 ***vrfysess = calloc(user_count, sizeof(VrfySessionD1**));
    for (i = 0;i < user_count;++i)
    {
        vrfysess[i] = calloc(sign_count, sizeof(VrfySessionD1*));
        assert(vrfysess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            vrfysess[i][j] = VrfySessionD1_new(keypair[i], sch);
            assert(vrfysess[i][j] != NULL);
        }
    }
    Signature ***sig = calloc(user_count, sizeof(Signature**));
    for (i = 0;i < user_count;++i)
    {
        sig[i] = calloc(sign_count, sizeof(Signature*));
        assert(sig[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            sig[i][j] = Signature_new(keypair[i], sch);
            assert(sig[i][j] != NULL);
        }
    }

    int msglen = bitlen_msg / 8;
    unsigned char *msg = malloc(msglen);
    assert(msg != NULL);

    /* Gen all keys */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    timerstop();

    /* Do all Signs-offline */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D1_sign_offline(sch, keypair[i], signsess[i][j], sig[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_off = getms();

    /* Do all Signs-online */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D1_sign_online(sch, keypair[i], signsess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_sign_on = getms();

    /* Do all Verifys-offline */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D1_vrfy_offline(sch, keypair[i], vrfysess[i][j]);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_off = getms();

    /* Do all Verifys-online */
    timerstart();
    for (i = 0; i < user_count; i++)
    {
        for (j = 0;j < sign_count;j++)
        {
            ret = Scheme_D1_vrfy_online(sch, keypair[i], vrfysess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    measured_vrfy_on = getms();

    if (ret_sign_tot != NULL) *ret_sign_tot = measured_sign_off + measured_sign_on;
    if (ret_sign_onl != NULL) *ret_sign_onl = measured_sign_on;
    if (ret_vrfy_tot != NULL) *ret_vrfy_tot = measured_vrfy_off + measured_vrfy_on;
    if (ret_vrfy_onl != NULL) *ret_vrfy_onl = measured_vrfy_on;

clean:
    free(sch);
    //A lot of things to clean
    return 0;
}


int testDeploy0(int verbose, int schid, int bitlen_sec,
	int bitlen_msg,
	int sign_count, int user_count,
	clock_t *ret_sign, clock_t *ret_vrfy, clock_t *ret_keygen)
{
	int ret,i,j;
	Scheme *sch = get_scheme_by_id(schid);
	if (sch == NULL) return -1;

	/* Warm up */
	ret = testD0OneUser(1, sch,
		bitlen_sec,
		bitlen_msg,
		NULL, NULL);

	assert(ret >= 0);

    KeyPair **keypair = calloc(user_count,sizeof(KeyPair*));
    for (i = 0;i < user_count;++i)
    {
        keypair[i] = KeyPair_new(sch, bitlen_sec);
        assert(keypair[i] != NULL);
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    SignSessionD0 ***signsess = calloc(user_count, sizeof(SignSessionD0**));
    for (i = 0;i < user_count;++i)
    {
        signsess[i] = calloc(sign_count, sizeof(SignSessionD0*));
        assert(signsess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            signsess[i][j] = SignSessionD0_new(keypair[i], sch);
            assert(signsess[i][j] != NULL);
        }
    }
    VrfySessionD0 ***vrfysess = calloc(user_count, sizeof(VrfySessionD0**));
    for (i = 0;i < user_count;++i)
    {
        vrfysess[i] = calloc(sign_count, sizeof(VrfySessionD0*));
        assert(vrfysess[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            vrfysess[i][j] = VrfySessionD0_new(keypair[i], sch);
            assert(vrfysess[i][j] != NULL);
        }
    }
    Signature ***sig = calloc(user_count, sizeof(Signature**));
    for (i = 0;i < user_count;++i)
    {
        sig[i] = calloc(sign_count, sizeof(Signature*));
        assert(sig[i] != NULL);
        for (j = 0;j < sign_count;++j)
        {
            sig[i][j] = Signature_new(keypair[i],sch);
            assert(sig[i][j] != NULL);
        }
    }

    int msglen = bitlen_msg / 8;
    unsigned char *msg = malloc(msglen);
    assert(msg != NULL);

    /* Gen all keys */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        ret = KeyPair_gen(keypair[i]);
        assert(ret == 0);
    }
    timerstop();
    if (ret_keygen != NULL) *ret_keygen = getms();

    /* Do all Signs */
    timerstart();
    for (i = 0;i < user_count;++i)
    {
        for (j = 0;j < sign_count;++j)
        {
            ret = Scheme_D0_sign(sch, keypair[i], signsess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
    }
    timerstop();
    if (ret_sign != NULL) *ret_sign = getms();

    /* Do all Verifys */
    timerstart();
    for (i = 0; i < user_count; i++)
	{
        for (j = 0;j < sign_count;j++)
        {
            Scheme_D0_vrfy(sch, keypair[i], vrfysess[i][j], sig[i][j], msg, msglen);
            assert(ret == 0);
        }
	}
    timerstop();
    if (ret_vrfy != NULL) *ret_vrfy = getms();

clean:
    free(sch);
    //A lot of things to clean
	return 0;
}


int testDeploy(int verbose, int schid, int deploy,
        int bitlen_sec,
	    int bitlen_msg,
	    int user_count, int sign_count,
	    clock_t *ret_gen, clock_t *ret_sign, clock_t *ret_vrfy)
{
    //TODO
    if (ret_gen!=NULL) *ret_gen = 888;
    if (ret_sign!=NULL) *ret_sign = 888;
    if (ret_vrfy!=NULL) *ret_vrfy = 888;
    return 0;
}


