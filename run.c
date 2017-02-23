#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "benchmark.h"

void print_usage(){
    printf(
"\nUSAGE:\n"
"   run     [-v] scheme [-sec n] [-msglen m] [-deploy d]\n"
"           [-sigcount x] [-usrcount y]\n"
"\n"
"DESCRIPTION\n"
"   This program times a message standard signature scheme you specified,\n"
"   and prints the time used to generate signatures, the time\n"
"   spent on the online phases, and the time used to verify signatures.\n"
"\n"
"\n"
"ARGUMENTS\n"
"   scheme      Specifies the scheme to be tested.\n"
"               scheme should be one of the following:\n"
"               ecdsa/ecrdsa/eckcdsa/ecsnor/eccdsa1/eccdsa2. \n\n"
"   -deploy d   Which deployment to use?\n"
"				Value d should be 0/10/20/21/30/31. (Default:30) \n\n"
"   -sec n      Security parameter.\n"
"               n should be 160/192/224/256/384/521.(Default: 256).\n\n"
"   -msglen m   message length in bit. (Default: n)\n\n"
"   -usrcount y number of key-pairs to test.(Default: 10)\n\n"
"   -sigcount x number of signatures to gen/verify per keypair. (Default:100)\n\n"
"   -csv        if given, output results as an CSV row\n\n");
}


void show_usage_and_exit_if(int v){
    if (v==0) return;
    print_usage();
    exit(1);
}


int main(int argc, char **argv)
{
    int i;
    
    int sch_id = -1;
    int bitlen_sec = 256;
	int bitlen_msg = -1;
    int sigcount = 100;
    int usrcount = 10;
    int verbose=1;
    int deploy=30;
    int simple=0;
    int csv=0;
    char *scheme_name=NULL;
    InitCrypt();

    for (i=1; i<argc; i++)
    {
        if (strcmp(argv[i], "-v")==0)
        {
            verbose=1;
        }
        else if (strcmp(argv[i], "-csv")==0)
        {
            csv=1;
        }
        else if (strcmp(argv[i], "-s")==0)
        {
            simple=1;
        }
        else if (strcmp(argv[i],"-vv")==0)
        {
            verbose=2;
        }
		else if (strcmp(argv[i], "-sec") == 0)
		{
			show_usage_and_exit_if(i == argc - 1);
			i++;
			bitlen_sec = atoi(argv[i]);
		}
		else if (strcmp(argv[i], "-deploy") == 0)
		{
			show_usage_and_exit_if(i == argc - 1);
			i++;
			deploy = atoi(argv[i]);
		}
		else if (strcmp(argv[i], "-msglen") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            bitlen_msg = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-sigcount") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            sigcount = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-usrcount") == 0)
        {
            show_usage_and_exit_if(i==argc-1);
            i++;
            usrcount = atoi(argv[i]);
        }
        else
        {
			if (strcmp(argv[i], "ecdsa") == 0)
            {
				sch_id = SCHID_EC_DSA;
                scheme_name = argv[i];
            }
            else if (strcmp(argv[i], "eckcdsa") == 0)
            {
                sch_id = SCHID_EC_KCDSA;
                scheme_name = argv[i];
            }
            else if (strcmp(argv[i], "eccdsa1") == 0)
            {
                sch_id = SCHID_EC_CDSA_I;
                scheme_name = argv[i];
            }
            else if (strcmp(argv[i], "eccdsa2") == 0)
            {
                sch_id = SCHID_EC_CDSA_II;
                scheme_name = argv[i];
            }
            else if (strcmp(argv[i], "ecrdsa") == 0)
            {
                sch_id = SCHID_EC_RDSA;
                scheme_name = argv[i];
            }
            else if (strcmp(argv[i], "ecsnor") == 0)
            {
                sch_id = SCHID_EC_SCHNORR;
                scheme_name = argv[i];
            }
            else
            {
                show_usage_and_exit_if(1);
                scheme_name = argv[i];
            }
        }
    }

    show_usage_and_exit_if(sch_id==-1);
	if (bitlen_msg == -1) bitlen_msg = bitlen_sec;
    

    clock_t gen_tot = 0;
    clock_t son_tot = 0;
    clock_t von_tot = 0;
    
    testDeploy(verbose, sch_id, deploy, bitlen_sec,
        bitlen_sec,
        usrcount, sigcount,
        &gen_tot, &son_tot, &von_tot);
    if (csv)
    {
        printf("%s,%d,%d,%d,%d,%d,%d,\n",
                scheme_name,
                deploy,
                usrcount,
                sigcount*usrcount,
                (int)gen_tot,
                (int)son_tot,
                (int)von_tot);
    }
    else
    {
        printf("\nsch=%s, "
                "deploy=%d, "
                "#usr=%d, "
                "#session=%d\n"
                "KeyGen      : %d\n"
                "Sign online : %d\n"
                "Vrfy online : %d\n",
                scheme_name,
                deploy,
                usrcount,
                sigcount*usrcount,
                (int)gen_tot,
                (int)son_tot,
                (int)von_tot);
    }
    return 0;
}
