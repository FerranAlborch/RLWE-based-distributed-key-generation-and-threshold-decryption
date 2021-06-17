#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gmp.h>
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/fmpz_poly.h>
#include <flint/fmpq.h>
#include <flint/fmpq_poly.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <math.h>
#include <time.h>
#include"functions.h"


/*NECESSARY LIBRARIES
*Openssl
*GMP
*MPFR
*FLINT
*/


/*TO COMPILE USE
*gcc keygen_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o keygen.out -O2
*/



/*DONE***************************************************************
*Name: decrypt
*
*Description: Returns m given u,v,s
*
*Arguments:
********************************************************************/
void decrypt(fmpz_poly_t m, fmpz_poly_t s, fmpz_poly_t u, fmpz_poly_t v,
							mpz_t q, int n) {
	fmpz_poly_t e;
	fmpz_poly_init(e);
	fmpz_poly_mul_Rq(e,s,u,n,q);
	fmpz_poly_sub(e,v,e);
	fmpz_p_mod(e,n,e,q);
	round_message(e,m,q,n);
	fmpz_poly_clear(e);
}

/*DONE******************************************************************
*Name: keygen_sim
*
*Decription: Simulates the distributed key generation
*
*Arguments:
*************************************************************************/
void keygen_sim(double **times, fmpz_poly_t **sshamir,
									fmpz_poly_t aE, fmpz_poly_t bE, fmpz_t KH[],
									int** allowedt1, int** allowedt, fmpz_poly_t lambda,
									int** matrixt1, int **key_map1, int binomt, mpf_t sigmakg,
									int binomu1, int binomt1, int u, int n, int t, mpz_t q, mpz_t interkg) {
	// We will split the key generation in 5 steps. Each step will be explained.

	// We create all the storage we will need
	fmpz_t **sNIVSS_keys;
	sNIVSS_keys = flint_malloc(u*sizeof(fmpz_t*));
	for(int i=0; i<u; ++i) {
		sNIVSS_keys[i] = flint_malloc(binomt*sizeof(fmpz_t));
		for(int j=0; j<binomt; ++j) fmpz_init(sNIVSS_keys[i][j]);
	}
	fmpz_t **eNIVSS_keys;
	eNIVSS_keys = flint_malloc(u*sizeof(fmpz_t*));
	for(int i=0; i<u; ++i) {
		eNIVSS_keys[i] = flint_malloc(binomt*sizeof(fmpz_t));
		for(int j=0; j<binomt; ++j) fmpz_init(eNIVSS_keys[i][j]);
	}
	fmpz_poly_t si[u],ei[u];
	char **commit_si;
	commit_si = malloc(u*sizeof(char*));
	for(int i=0; i<u; ++i) {
		commit_si[i] = malloc((2*SHA512_DIGEST_LENGTH+1)*sizeof(char));
	}
	char **commit_ei;
	commit_ei = malloc(u*sizeof(char*));
	for(int i=0; i<u; ++i) {
		commit_ei[i] = malloc((2*SHA512_DIGEST_LENGTH+1)*sizeof(char));
	}
	fmpz_t **KHj;
	KHj = flint_malloc(u*sizeof(fmpz_t*));
	for(int i=0; i<u; ++i) {
		KHj[i] = flint_malloc(binomt*sizeof(fmpz_t));
		for(int j=0; j<binomt; ++j) fmpz_init(KHj[i][j]);
	}
	fmpz_t ***KHj_shares;
	KHj_shares = flint_malloc(u*sizeof(fmpz_t**));
	for(int i=0; i<u; ++i) {
		KHj_shares[i] = flint_malloc(binomt*sizeof(fmpz_t*));
		for(int j=0; j<binomt; ++j) {
			KHj_shares[i][j] = flint_malloc(u*sizeof(fmpz_t));
			for(int k=0; k<u; ++k) fmpz_init(KHj_shares[i][j][k]);
		}
	}
	char ****commit_KHj_shares;
	commit_KHj_shares = malloc(u*sizeof(char***));
	for(int i=0; i<u; ++i) {
		commit_KHj_shares[i] = malloc(binomt*sizeof(char**));
		for(int j=0; j<binomt; ++j) {
			commit_KHj_shares[i][j] = malloc(u*sizeof(char*));
			for(int k=0; k<u; ++k) {
				commit_KHj_shares[i][j][k] = malloc((2*SHA512_DIGEST_LENGTH+1)*sizeof(char));
			}
		}
	}
	fmpz_poly_t aEj[u];
	fmpz_poly_t **aEj_shares;
	aEj_shares = flint_malloc(u*sizeof(fmpz_poly_t*));
	for(int i=0; i<u; ++i) {
		aEj_shares[i] = flint_malloc(u*sizeof(fmpz_poly_t));
		for(int j=0; j<u; ++j) fmpz_poly_init(aEj_shares[i][j]);
	}
	char ***commit_aEj_shares;
	commit_aEj_shares = malloc(u*sizeof(char**));
	for(int i=0; i<u; ++i) {
		commit_aEj_shares[i] = malloc(u*sizeof(char*));
		for(int j=0; j<u; ++j) {
			commit_aEj_shares[i][j] = malloc((2*SHA512_DIGEST_LENGTH+1)*sizeof(char));
		}
	}



	//printf("Step 1\n");
	// First step. For every player we sample all values from their respective distributions
	// and then commit them to send them.
	/*fmpz_poly_t rNIVSSs[u];
	fmpz_poly_t rNIVSSe[u];
	fmpz_poly_t aux_s;
	fmpz_poly_t aux_s2[u];
	fmpz_poly_t aux_e;
	fmpz_poly_t aux_e2[u];
	fmpz_poly_init(aux_s);
	for(int i=0; i<u; ++i) fmpz_poly_init(aux_s2[i]);
	fmpz_poly_init(aux_e);
	for(int i=0; i<u; ++i) fmpz_poly_init(aux_e2[i]);*/
	for(int i=0; i<u; ++i) {
		// Begin timer
		clock_t begin = clock();

		//Sample contribution to s and to e from the discrete Gaussian
		fmpz_poly_init(si[i]);
		fmpz_poly_init(ei[i]);
		disc_gauss_Rq(sigmakg,si[i],n,q);
		disc_gauss_Rq(sigmakg,ei[i],n,q);
		//fmpz_poly_set(aux_s2[i],si[i]);
		//fmpz_poly_set(aux_e2[i],ei[i]);
		//fmpz_poly_add(aux_s,aux_s,si[i]);
		//fmpz_poly_add(aux_e,aux_e,ei[i]);

		// Produce the keys for the NIVSS for both of them
		for(int j=0; j<binomt; ++j) {
			rand_Zq(sNIVSS_keys[i][j],n,q);
			rand_Zq(eNIVSS_keys[i][j],n,q);
		}
		

		// Compute and commit sj-r and ej-r
		//fmpz_poly_init(rNIVSSs[i]);
		//fmpz_poly_init(rNIVSSe[i]);
		fmpz_poly_t auxNIVSS;
		for(int j=0; j<binomt; ++j) {
			fmpz_poly_init(auxNIVSS);
			PRF(sNIVSS_keys[i][j],lambda,auxNIVSS,interkg,n);
			fmpz_poly_sub(si[i],si[i],auxNIVSS);
			//fmpz_poly_add(rNIVSSs[i],rNIVSSs[i],auxNIVSS);
			//fmpz_p_mod(si[i],n,si[i],q);
			fmpz_poly_clear(auxNIVSS);
			
			fmpz_poly_init(auxNIVSS);
			PRF(eNIVSS_keys[i][j],lambda,auxNIVSS,interkg,n);
			fmpz_poly_sub(ei[i],ei[i],auxNIVSS);
			//fmpz_poly_add(rNIVSSe[i],rNIVSSe[i],auxNIVSS);
			//fmpz_p_mod(ei[i],n,ei[i],q);
			fmpz_poly_clear(auxNIVSS);
		}
		
		
		
		char *stringsi=fmpz_poly_get_str(si[i]);
		int silen=strlen(stringsi);
		unsigned char hashsi[SHA512_DIGEST_LENGTH];
		commit_sha2(stringsi,silen,hashsi,commit_si[i]);
		free(stringsi);
		char *stringei=fmpz_poly_get_str(ei[i]);
		int eilen=strlen(stringei);
		unsigned char hashei[SHA512_DIGEST_LENGTH];
		commit_sha2(stringei,eilen,hashei,commit_ei[i]);
		free(stringei);
		

		// Sample the KHj, compute Shamir shares and commit them
		for(int j=0; j<binomt; ++j) {
			rand_Zq(KHj[i][j],n,q);
			gen_shamir_Zq(KHj_shares[i][j],KHj[i][j],n,u,t,q);
			for(int k=0; k<u; ++k) {
				char *KHjsstring = fmpz_get_str(NULL,2,KHj_shares[i][j][k]);
				int KHjlen = strlen(KHjsstring);
				unsigned char hashKH[SHA512_DIGEST_LENGTH];
				commit_sha2(KHjsstring,KHjlen,hashKH,commit_KHj_shares[i][j][k]);
				free(KHjsstring);
			}
		}


		// Sample aEj, compute Shamir shares and commit them
		fmpz_poly_init(aEj[i]);
		rand_Rq(aEj[i],n,q);
		gen_shamir_Rq(aEj_shares[i],aEj[i],n,u,t,q);
		for(int j=0; j<u; ++j) {
			char *aEjsstring = fmpz_poly_get_str(aEj_shares[i][j]);
			int aEjlen = strlen(aEjsstring);
			unsigned char hashaEj[SHA512_DIGEST_LENGTH];
			commit_sha2(aEjsstring,aEjlen,hashaEj,commit_aEj_shares[i][j]);
			free(aEjsstring);
		}

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[0][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}
	

	// Free storage for: KHj, aEj (beware if you want to verify)
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomt; ++j) {
			fmpz_clear(KHj[i][j]);
		}
		flint_free(KHj[i]);
		fmpz_poly_clear(aEj[i]);
	}
	flint_free(KHj);


	//printf("Step 2\n");
	// Second step. Every player verifies all commitments sent to him
	for(int i=0; i<u; ++i) {
		// Begin timer
		clock_t begin = clock();

		for(int l=0; l<u; ++l) {
			// Verify commitments of si and ei
			char *stringsi=fmpz_poly_get_str(si[l]);
			int silen=strlen(stringsi);
			int verify_si=verify_commit_sha2(commit_si[l],stringsi,silen);
			if (verify_si==0) printf("ERROR: Commitment of sj done by player %d for player %d does not match\n",l,i);
			free(stringsi);
			char *stringei=fmpz_poly_get_str(ei[l]);
			int eilen=strlen(stringei);
			int verify_ei=verify_commit_sha2(commit_ei[l],stringei,eilen);
			if (verify_si==0) printf("ERROR: Commitment of ej done by player %d for player %d does not match\n",l,i);
			free(stringei);


			// Verify commitments of KHj shares
			for(int j=0; j<binomt; ++j) {
				char *KHjsstring = fmpz_get_str(NULL,2,KHj_shares[l][j][i]);
				int KHjlen = strlen(KHjsstring);
				int verify_KHj=verify_commit_sha2(commit_KHj_shares[l][j][i],KHjsstring,KHjlen);
				free(KHjsstring);
				//printf("Returns 1 if the KHj share commitment is verified, 0 otherwise: %d\n",verify_KHj);
			}


			// Verify commitments of aEj shares
			char *aEjsstring = fmpz_poly_get_str(aEj_shares[l][i]);
			int aEjlen = strlen(aEjsstring);
			int verify_aEj=verify_commit_sha2(commit_aEj_shares[l][i],aEjsstring,aEjlen);
			free(aEjsstring);
			//printf("Returns 1 if the aEj share commitment is verified, 0 otherwise: %d\n",verify_aEj);
		}

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[1][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}


	// Free storage for: commit_si, commit_ei, commit_KHj_shares, commit_aEj_shares
	for(int i=0; i<u; ++i) {
		free(commit_si[i]);
		free(commit_ei[i]);
		for(int j=0; j<binomt; ++j) {
			for(int k=0; k<u; ++k) {
				free(commit_KHj_shares[i][j][k]);
			}
			free(commit_KHj_shares[i][j]);
		}
		free(commit_KHj_shares[i]);
		for(int j=0; j<u; ++j) {
			free(commit_aEj_shares[i][j]);
		}
		free(commit_aEj_shares[i]);
	}
	free(commit_si);
	free(commit_ei);
	free(commit_KHj_shares);
	free(commit_aEj_shares);



	// Generate storage for: KH_shares, sj_add, ej_add, small_s_sham, small_e_sham
	// aE_shares
	fmpz_t **KH_shares;
	KH_shares = flint_malloc(binomt*sizeof(fmpz_t*));
	for(int i=0; i<binomt; ++i) {
		KH_shares[i] = flint_malloc(u*sizeof(fmpz_t));
		for(int j=0; j<u; ++j) fmpz_init(KH_shares[i][j]);
	}
	fmpz_poly_t ***sj_add;
	sj_add = flint_malloc(u*sizeof(fmpz_poly_t**));
	for(int i=0; i<u; ++i) {
		sj_add[i] = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
		for(int j=0; j<binomt1; ++j) {
			sj_add[i][j] = flint_malloc(u*sizeof(fmpz_poly_t));
			for(int k=0; k<u; ++k) fmpz_poly_init(sj_add[i][j][k]);
		}
	}
	fmpz_poly_t ***ej_add;
	ej_add = flint_malloc(u*sizeof(fmpz_poly_t**));
	for(int i=0; i<u; ++i) {
		ej_add[i] = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
		for(int j=0; j<binomt1; ++j) {
			ej_add[i][j] = flint_malloc(u*sizeof(fmpz_poly_t));
			for(int k=0; k<u; ++k) fmpz_poly_init(ej_add[i][j][k]);
		}
	}
	fmpz_poly_t ****small_s_sham;
	small_s_sham = flint_malloc(u*sizeof(fmpz_poly_t***));
	for(int i=0; i<u; ++i) {
		small_s_sham[i] = flint_malloc(binomt1*sizeof(fmpz_poly_t**));
		for(int j=0; j<binomt1; ++j) {
			small_s_sham[i][j] = flint_malloc(u*sizeof(fmpz_poly_t*));
			for(int k=0; k<u; ++k) {
				small_s_sham[i][j][k] = flint_malloc(u*sizeof(fmpz_poly_t));
				for(int l=0; l<u; ++l) {
					fmpz_poly_init(small_s_sham[i][j][k][l]);
				}
			}
		}
	}
	fmpz_poly_t ****small_e_sham;
	small_e_sham = flint_malloc(u*sizeof(fmpz_poly_t***));
	for(int i=0; i<u; ++i) {
		small_e_sham[i] = flint_malloc(binomt1*sizeof(fmpz_poly_t**));
		for(int j=0; j<binomt1; ++j) {
			small_e_sham[i][j] = flint_malloc(u*sizeof(fmpz_poly_t*));
			for(int k=0; k<u; ++k) {
				small_e_sham[i][j][k] = flint_malloc(u*sizeof(fmpz_poly_t));
				for(int l=0; l<u; ++l) {
					fmpz_poly_init(small_e_sham[i][j][k][l]);
				}
			}
		}
	}
	fmpz_poly_t aE_shares[u];

	//printf("Step 3\n");
	// Third step. For s and e we do ?. For KH and aE every player adds all the
	// shares he received and sends rhe share to the appropriate players
	for(int i=0; i<u; ++i) {
		// Begin timer
		clock_t begin = clock();

		// Verify that every sj-r and ej-r are in the interval needed
		fmpz_t max;
		fmpz_init(max);
		fmpz_t interkgf;
		fmpz_init(interkgf);
		fmpz_set_mpz(interkgf,interkg);
		fmpz_mul_ui(max,interkgf,binomt);
		fmpz_clear(interkgf);
		fmpz_t coeff;
		for(int k=0; k<u; ++k) {
			for(int l=0; l<n; ++l) {
				fmpz_init(coeff);
				fmpz_poly_get_coeff_fmpz(coeff,si[k],l);
				if(fmpz_cmp(coeff,max)>0) printf("ERROR: coefficient %d of masked contribution for s of player %d is too big.",l,k);

				fmpz_init(coeff);
				fmpz_poly_get_coeff_fmpz(coeff,ei[k],l);
				if(fmpz_cmp(coeff,max)>0) printf("ERROR: coefficient %d of masked contribution for e of player %d is too big.",l,k);
				fmpz_clear(coeff);
			}
		}
		fmpz_clear(max);

		// For e and s we compute for every subset the PRSS share rj
		for(int k=0; k<u; ++k) {
			for(int j=0; j<binomu1; ++j) {
				int column= allowedt1[i][j];

				//Compute the PRSS share of player i in the subset column
				int* states = (int*)malloc(u * sizeof(int));
				int* statee = (int*)malloc(u * sizeof(int));
				for(int l=0; l<u; ++l) {
					states[l]=0;
					statee[l]=0;
				}
				int order = 0;
				int found = 0;
				for(int l=0; l<u; ++l) {
					int mod = (column+l)%u;
					if(found == 0 && mod == i) found = 1;
					if(found ==0 && matrixt1[mod][column]==1) {
						states[order]=mod+1;
						statee[order]=mod+1;
						order=order+1;
					}
				}

				int* indexess = (int*)malloc(u * sizeof(int));
				int* indexese = (int*)malloc(u * sizeof(int));
				int count = 0;
				for(int l=1; l<u+1; ++l) {
					if(l!=i+1) {
						int found = 0;
						for(int p =0; p<order; ++p){
							if(states[p]==l) found =1;
						}
						if(found == 0) {
							indexess[count] = l;
							indexese[count] = l;
							count=count+1;
						}
					}
				}

				PRSS_share(states,indexess,t-order,sj_add[k][column][i],key_map1,sNIVSS_keys[k],binomt,order,u-(order+1),lambda,interkg,n);

				PRSS_share(statee,indexese,t-order,ej_add[k][column][i],key_map1,eNIVSS_keys[k],binomt,order,u-(order+1),lambda,interkg,n);

				free(states);
				free(indexess);
				free(statee);
				free(indexese);
			}
		}


		// We start the additive to shamir conversion of PRSS shares of s and e by making a
		// Shamir share of every contribution
		for(int j=0; j<binomu1; ++j) {
			int column = allowedt1[i][j];
			for(int k=0; k<u; ++k) {
				gen_shamir_Rq(small_s_sham[k][column][i],sj_add[k][column][i],n,u,t,q);
				gen_shamir_Rq(small_e_sham[k][column][i],ej_add[k][column][i],n,u,t,q);
			}
		}


		// We add all the KHj shares received
		for(int j=0; j<binomt; ++j) {
			for(int k=0; k<u; ++k) fmpz_add(KH_shares[j][i],KH_shares[j][i],KHj_shares[k][j][i]);
		}


		// We add all the aEj shares received
		fmpz_poly_init(aE_shares[i]);
		for(int j=0; j<u; ++j) fmpz_poly_add(aE_shares[i],aE_shares[i],aEj_shares[j][i]);

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[2][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}


	// Free storage for: sNIVSS_keys, eNIVSS_keys, KHj_shares, aEj_shares, sj_add,
	// ej_add (beware if you want to verify)
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomt; ++j) {
			fmpz_clear(sNIVSS_keys[i][j]);
			fmpz_clear(eNIVSS_keys[i][j]);
			for(int k=0; k<u; ++k) {
				fmpz_clear(KHj_shares[i][j][k]);
			}

			flint_free(KHj_shares[i][j]);
		}
		flint_free(sNIVSS_keys[i]);
		flint_free(eNIVSS_keys[i]);
		flint_free(KHj_shares[i]);
		for(int j=0; j<u; ++j) {
			fmpz_poly_clear(aEj_shares[i][j]);
		}
		flint_free(aEj_shares[i]);
		for(int j=0; j<binomt1; ++j) {
			for(int k=0; k<u; ++k) {
				fmpz_poly_clear(sj_add[i][j][k]);
				fmpz_poly_clear(ej_add[i][j][k]);
			}
			flint_free(sj_add[i][j]);
			flint_free(ej_add[i][j]);
		}
		flint_free(sj_add[i]);
		flint_free(ej_add[i]);
	}
	flint_free(sNIVSS_keys);
	flint_free(eNIVSS_keys);
	flint_free(KHj_shares);
	flint_free(aEj_shares);
	flint_free(sj_add);
	flint_free(ej_add);


	// Verify the PRSS is correct
	/*for(int i=0; i<u; ++i) {
		fmpz_poly_t auxsss[binomt1];
		int bigg = 1;
		for(int j=0; j<binomt1; ++j) {
			fmpz_poly_init(auxsss[j]);
			// Find the vector of players
			int players[t+1];
			int count = 0;
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][j]==1) {
					players[count]=k+1;
					count=count+1;
				}
			}
			for(int k=0; k<t+1; ++k) {
				fmpz_poly_add(auxsss[j],auxsss[j],sj_add[i][j][players[k]-1]);
			}
			int compsss=fmpz_poly_equal(rNIVSSs[i],auxsss[j]);
			printf("Column %d: Returns 1 if the PRSS is correct, 0 otherwise: %d\n",j+1,compsss);
			if(fmpz_poly_equal(auxsss[j],auxsss[0])==0) bigg = 0;
		}
		printf("Returns 1 if all si are equal, 0 otherwise: %d\n", bigg);
		printf("\n");
	}*/

	/*for(int i=0; i<u; ++i) {
		fmpz_poly_t auxess[binomt1];
		int bigg = 1;
		for(int j=0; j<binomt1; ++j) {
			fmpz_poly_init(auxess[j]);
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][j]==1) fmpz_poly_add(auxess[j],auxess[j],ej_add[i][j][k]);
			}
			int compess=fmpz_poly_equal(rNIVSSe[i],auxess[j]);
			printf("Column %d: Returns 1 if the PRSS is correct, 0 otherwise: %d\n",j+1,compess);
			if(fmpz_poly_equal(auxess[j],auxess[0])==0) bigg = 0;
		}
		printf("Returns 1 if all si are equal, 0 otherwise: %d\n", bigg);
		printf("\n");
	}*/

	// Verify the shamir share is correct
	/*fmpz_poly_t element;
	for(int j=0; j<binomt1; ++j) {
		// Find the vector of players
		int players[t+1];
		int count = 0;
		for(int k=0; k<u; ++k) {
			if(matrixt1[k][j]==1) {
				players[count]=k+1;
				count=count+1;
			}
		}
		for(int i=0; i<u; ++i) {
			for(int k=0; k<u; ++k) {
				fmpz_poly_init(element);
				compute_shamir_Rq(element,small_s_sham[k][j][i],players,t,u,n,q);
				int compare_guai = fmpz_poly_equal(element,sj_add[k][j][i]);
				printf("Returns 1 if the small shamir is correct, 0 otherwise: %d\n", compare_guai);
			}
		}
	}*/



	// Generate storage for: sj_sham, ej_sham, eshamir, bE_share
	fmpz_poly_t ***sj_sham;
	sj_sham = flint_malloc(u*sizeof(fmpz_poly_t**));
	for(int i=0; i<u; ++i) {
		sj_sham[i] = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
		for(int j=0; j<binomt1; ++j) {
			sj_sham[i][j] = flint_malloc(u*sizeof(fmpz_poly_t));
			for(int k=0; k<u; ++k) {
				fmpz_poly_init(sj_sham[i][j][k]);
			}
		}
	}
	fmpz_poly_t ***ej_sham;
	ej_sham = flint_malloc(u*sizeof(fmpz_poly_t**));
	for(int i=0; i<u; ++i) {
		ej_sham[i] = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
		for(int j=0; j<binomt1; ++j) {
			ej_sham[i][j] = flint_malloc(u*sizeof(fmpz_poly_t));
			for(int k=0; k<u; ++k) {
				fmpz_poly_init(ej_sham[i][j][k]);
			}
		}
	}
	fmpz_poly_t **eshamir;
	eshamir = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
	for(int i=0; i<binomt1; ++i) {
		eshamir[i] = flint_malloc(u*sizeof(fmpz_poly_t));
		for(int j=0; j<u; ++j) {
			fmpz_poly_init(eshamir[i][j]);
		}
	}
	fmpz_poly_t **bE_share;
	bE_share = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
	for(int i=0; i<binomt1; ++i) {
		bE_share[i] = flint_malloc(u*sizeof(fmpz_poly_t));
		for(int j=0; j<u; ++j) {
			fmpz_poly_init(bE_share[i][j]);
		}
	}

	//printf("Step 4\n");
	// Fourth step. For s and e ?. For KH and aE we reconstruct them
	for(int i=0; i<u; ++i) {
		// Begin timer
		clock_t begin = clock();

		// We compute the shamir shares of s and e by adding all the shamir shares of
		// the PRSS contribution, then adding this to si, ei and finally adding all these
		fmpz_poly_t aux_sj_sham;
		fmpz_poly_t aux_ej_sham;
		for(int j=0; j<binomu1; ++j) {
			int column = allowedt1[i][j];
			// Find the vector of players
			int players[t+1];
			int count = 0;
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][column]==1) {
					players[count]=k+1;
					count=count+1;
				}
			}
			for(int k=0; k<u; ++k) {
				fmpz_poly_init(aux_sj_sham);
				fmpz_poly_init(aux_ej_sham);
				for(int l=0; l<t+1; ++l) {
					fmpz_poly_add(aux_sj_sham,aux_sj_sham,small_s_sham[k][column][players[l]-1][i]);
					fmpz_poly_add(aux_ej_sham,aux_ej_sham,small_e_sham[k][column][players[l]-1][i]);
				}
				fmpz_poly_set(sj_sham[k][column][i],aux_sj_sham);
				fmpz_poly_set(ej_sham[k][column][i],aux_ej_sham);
				fmpz_poly_add(sj_sham[k][column][i],sj_sham[k][column][i],si[k]);
				fmpz_poly_add(ej_sham[k][column][i],ej_sham[k][column][i],ei[k]);
				fmpz_poly_clear(aux_sj_sham);
				fmpz_poly_clear(aux_ej_sham);
			}
		}
		for(int j=0; j<binomu1; ++j) {
			int column=allowedt1[i][j];
			fmpz_poly_init(sshamir[column][i]);
			fmpz_poly_init(eshamir[column][i]);
			for(int k=0; k<u; ++k) {
				fmpz_poly_add(sshamir[column][i],sshamir[column][i],sj_sham[k][column][i]);
				fmpz_poly_add(eshamir[column][i],eshamir[column][i],ej_sham[k][column][i]);
			}
		}


		// Retrieve KH
		fmpz_t **auxKH;
		auxKH = flint_malloc(binomt*sizeof(fmpz_t*));
		for(int j=0; j<binomt; ++j) {
			auxKH[j] = flint_malloc(binomt1*sizeof(fmpz_t));
			for(int l=0; l<binomt1; ++l) fmpz_init(auxKH[j][l]);
		}
		int binomut1 = binomial(u-1,u-t-1);
		for(int j=0; j<binomut1; ++j) {
			int column = allowedt[i][j];
			int compare_KH = 1;
			for(int l=0; l<binomt1; ++l) {
				int players[t+1];
				int count = 0;
				for(int k=0; k<u; ++k) {
					if(matrixt1[k][l]==1) {
						players[count]=k+1;
						count=count+1;
					}
				}
				compute_shamir_Zq(auxKH[column][l],KH_shares[column],players,t,u,n,q);
				if(fmpz_equal(auxKH[column][l],auxKH[column][0])==0) compare_KH = 0;
			}
			//printf("Returns 1 if all KH are equal, 0 otherwise: %d\n",compare_KH);
			fmpz_init(KH[column]);
			if(compare_KH==1) fmpz_set(KH[column],auxKH[column][0]);
		}
		for(int j=0; j<binomt; ++j) {
			for(int k=0; k<binomt1; ++k) fmpz_clear(auxKH[j][k]);
			flint_free(auxKH[j]);
		}
		flint_free(auxKH);


		// Retrieve aE
		fmpz_poly_t auxaE[binomt1];
		for(int j=0; j<binomt1; ++j) fmpz_poly_init(auxaE[j]);
		int compare_aE = 1;
		for(int j=0; j<binomt1; ++j) {
			int players[t+1];
			int count = 0;
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][j]==1) {
					players[count]=k+1;
					count=count+1;
				}
			}
			compute_shamir_Rq(auxaE[j],aE_shares,players,t,u,n,q);
			if(fmpz_poly_equal(auxaE[j],auxaE[0])==0) compare_aE = 0;
		}
		//printf("Returns 1 if all aE are equal, 0 otherwise: %d\n",compare_aE);
		if(compare_aE==1) fmpz_poly_set(aE,auxaE[0]);
		fmpz_p_mod(aE,n,aE,q);
		for(int j=0; j<binomt1; ++j) fmpz_poly_clear(auxaE[j]);


		// Compute the shares of bE for every allowed subset of players
		for(int j=0; j<binomu1; ++j) {
			int column=allowedt1[i][j];
			fmpz_poly_mul_Rq(bE_share[column][i],aE,sshamir[column][i],n,q);
			fmpz_poly_add(bE_share[column][i],bE_share[column][i],eshamir[column][i]);
		}

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[3][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}


	// Free storage for: KH_shares, small_s_sham, sj_sham, ej_sham, eshamir, si,
	// ei, aE_shares (beware if you want to verify)
	for(int i=0; i<binomt; ++i) {
		for(int j=0; j<u; ++j) {
			fmpz_clear(KH_shares[i][j]);
		}
		flint_free(KH_shares[i]);
	}
	flint_free(KH_shares);
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomt1; ++j) {
			for(int k=0; k<u; ++k) {
				for(int l=0; l<u; ++l) {
					fmpz_poly_clear(small_s_sham[i][j][k][l]);
					fmpz_poly_clear(small_e_sham[i][j][k][l]);
				}
				flint_free(small_s_sham[i][j][k]);
				flint_free(small_e_sham[i][j][k]);
				fmpz_poly_clear(sj_sham[i][j][k]);
				fmpz_poly_clear(ej_sham[i][j][k]);
			}
			flint_free(small_s_sham[i][j]);
			flint_free(small_e_sham[i][j]);
			flint_free(sj_sham[i][j]);
			flint_free(ej_sham[i][j]);
		}
		flint_free(small_s_sham[i]);
		flint_free(small_e_sham[i]);
		flint_free(sj_sham[i]);
		flint_free(ej_sham[i]);

		fmpz_poly_clear(si[i]);
		fmpz_poly_clear(ei[i]);
		fmpz_poly_clear(aE_shares[i]);
	}
	flint_free(small_s_sham);
	flint_free(small_e_sham);
	flint_free(sj_sham);
	flint_free(ej_sham);
	for(int i=0; i<binomt1; ++i) {
		for(int j=0; j<u; ++j) {
			fmpz_poly_clear(eshamir[i][j]);
		}
		flint_free(eshamir[i]);
	}
	flint_free(eshamir);


	/*fmpz_t superaux[binomt];
	for(int j=0; j<binomt; ++j) {
		fmpz_init(superaux[j]);
		for(int i=0; i<u; ++i) {
			fmpz_add(superaux[j],superaux[j],KHj[i][j]);
		}
		int supercompare=fmpz_equal(superaux[j],KH[j]);
		printf("Returns 1 if KH is correctly generated, 0 otherwise: %d\n",supercompare);
	}*/

	// Verification: compute_shamir de sj_sham[i][j] = rNIVSS[i] per tot j allowed
	/*fmpz_poly_t reconstruct_ssum;
	for(int j=0; j<binomt1; ++j) {
		// Find the vector of players
		int players[t+1];
		int count = 0;
		for(int k=0; k<u; ++k) {
			if(matrixt1[k][j]==1) {
				players[count]=k+1;
				count=count+1;
			}
		}
		for(int i=0; i<u; ++i) {
			fmpz_poly_init(reconstruct_ssum);
			compute_shamir_Rq(reconstruct_ssum,sj_sham[i][j],players,t,u,n,q);
			int compare_ssum = fmpz_poly_equal(reconstruct_ssum,aux_s2[i]);
			printf("Return 1 if sj_sham works, 0 otherwise: %d\n", compare_ssum);
		}
	}
	printf("\n");*/

	/*fmpz_poly_t reconstruct_esum;
	for(int j=0; j<binomt1; ++j) {
		// Find the vector of players
		int players[t+1];
		int count = 0;
		for(int k=0; k<u; ++k) {
			if(matrixt1[k][j]==1) {
				players[count]=k+1;
				count=count+1;
			}
		}
		for(int i=0; i<u; ++i) {
			fmpz_poly_init(reconstruct_esum);
			compute_shamir_Rq(reconstruct_esum,ej_sham[i][j],players,t,u,n,q);
			int compare_esum = fmpz_poly_equal(reconstruct_esum,aux_e2[i]);
			printf("Return 1 if ej_sham works, 0 otherwise: %d\n", compare_esum);
		}
	}
	printf("\n");*/

	// Verification: que tots els shamir de s reconstrueixin el mateix
	/*fmpz_poly_t reconstruct_s[binomt1];
	//int compare_e = 1;
	for(int i=0; i<binomt1; ++i) {
		fmpz_poly_init(reconstruct_s[i]);
		// Find the vector of players
		int players[t+1];
		int count = 0;
		for(int k=0; k<u; ++k) {
			if(matrixt1[k][i]==1) {
				players[count]=k+1;
				count=count+1;
			}
		}
		compute_shamir_Rq(reconstruct_s[i],sshamir[i],players,t,u,n,q);
		//if(fmpz_poly_equal(reconstruct_e[i],reconstruct_e[0])==0) compare_e = 0;
		int compare_s = fmpz_poly_equal(reconstruct_s[i],aux_s);
		printf("Returns 1 if sshamir is correct, 0 otherwise: %d\n", compare_s);
	}
	printf("\n");*/

	/*fmpz_poly_t reconstruct_e[binomt1];
	//int compare_e = 1;
	for(int i=0; i<binomt1; ++i) {
		fmpz_poly_init(reconstruct_e[i]);
		// Find the vector of players
		int players[t+1];
		int count = 0;
		for(int k=0; k<u; ++k) {
			if(matrixt1[k][i]==1) {
				players[count]=k+1;
				count=count+1;
			}
		}
		compute_shamir_Rq(reconstruct_e[i],eshamir[i],players,t,u,n,q);
		//if(fmpz_poly_equal(reconstruct_e[i],reconstruct_e[0])==0) compare_e = 0;
		int compare_e = fmpz_poly_equal(reconstruct_e[i],aux_e);
		printf("Returns 1 if eshamir is correct, 0 otherwise: %d\n", compare_e);
	}*/


	//printf("Step 5\n");
	// Fifth step. Recover bE
	for(int i=0; i<u; ++i) {
		// Begin timer
		clock_t begin = clock();

		fmpz_poly_t auxbE[binomt1];
		for(int j=0; j<binomt1; ++j) fmpz_poly_init(auxbE[j]);
		int compare_bE = 1;
		for(int j=0; j<binomt1; ++j) {
			int players[t+1];
			int count = 0;
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][j]==1) {
					players[count]=k+1;
					count=count+1;
				}
			}
			compute_shamir_Rq(auxbE[j],bE_share[j],players,t,u,n,q);
			if(fmpz_poly_equal(auxbE[j],auxbE[0])==0) compare_bE = 0;
		}
		//printf("Returns 1 if all bE are equal, 0 otherwise: %d\n",compare_bE);
		if(compare_bE==1) fmpz_poly_set(bE,auxbE[0]);
		fmpz_p_mod(bE,n,bE,q);
		for(int j=0; j<binomt1; ++j) fmpz_poly_clear(auxbE[j]);

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[4][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}

	/*fmpz_poly_t aux_bE;
	fmpz_poly_init(aux_bE);
	fmpz_poly_mul_Rq(aux_bE,aE,aux_s,n,q);
	fmpz_poly_add(aux_bE,aux_bE,aux_e);
	fmpz_p_mod(aux_bE,n,aux_bE,q);
	int compare_bEfinal = fmpz_poly_equal(bE,aux_bE);
	printf("Returns 1 if the bE is correctly generated, 0 otherwise: %d\n",compare_bEfinal);*/


	// We free storage for:  bE_share
	for(int i=0; i<binomt1; ++i) {
		for(int j=0; j<u; ++j) {
			fmpz_poly_clear(bE_share[i][j]);
		}
		flint_free(bE_share[i]);
	}
	flint_free(bE_share);
}


int main(int argc, char *argv[]) {
	//We set default float precission to 2048
	mpf_set_default_prec(2048);
	
	//Changeable parameters: n,q,u,t,repetitions
	int n = atoi(argv[1]);
	int np=4;
	mpz_t q;
	mpz_t qp;
	mpz_init_set_str(qp, "17", 10);
	mpz_init_set_str(q, "1267650600228229401496703205653", 10);
	int u= atoi(argv[2]);
	int t= atoi(argv[3]);
	int repetitions=1;

	//We set the general parameters sigmaenc, sigmakg, interdec, interkg and seed
	int binomt = binomial(u,t);
	mpz_t interdec,interkg;
	mpz_init(interdec);
	mpz_init(interkg);
	mpf_t sigma,sigmaenc,sigmakg,sqrtu,aux1,auxsigma,auxinter,qfloat,sqrtq,interdecfloat,interkgfloat;
	mpf_init(sigma);
	mpf_init(sigmaenc);
	mpf_init(sigmakg);
	mpf_init(sqrtu);
	mpf_init(aux1);
	mpf_init(auxsigma);
	mpf_init(auxinter);
	mpf_init(qfloat);
	mpf_init(sqrtq);
	mpf_init(interdecfloat);
	mpf_init(interkgfloat);

	mpf_set_z(qfloat,q);
	mpf_sqrt_ui(sqrtu,u);
	mpf_sqrt(sqrtq,qfloat);
	mpf_sqrt(aux1,qfloat);
	mpf_sqrt(auxinter,aux1);
	mpf_mul_ui(aux1,aux1,4*n);
	mpf_sub_ui(auxinter,auxinter,1);
	mpf_mul(auxinter,auxinter,qfloat);
	mpf_mul_ui(auxsigma,qfloat,2*n+1);
	mpf_mul(sigmaenc,aux1,auxsigma);
	mpf_ui_div(sigmaenc,1,sigmaenc);
	mpf_sqrt(sigmaenc,sigmaenc);
	mpf_div(sigmakg,sigmaenc,sqrtu);
	//mpf_div_ui(sigmakg,sigmakg,10000);
	mpf_mul_ui(interdecfloat,aux1,binomt);
	mpf_div(interdecfloat,auxinter,interdecfloat);
	mpf_mul_ui(interdecfloat,interdecfloat,n);
	mpz_set_f(interdec,interdecfloat);

	mpf_div_ui(interkgfloat,qfloat,4*(2*n+1)*u*binomt);
	mpf_div(interkgfloat,interkgfloat,sqrtq);
	//mpz_set_f(interkg,interkgfloat);
	//mpz_set_f(interkg,qfloat);
	mpz_set(interkg,interdec);
	mpf_set_d(sigma,1.0);
	mpf_clear(aux1);
	mpf_clear(sqrtu);
	mpf_clear(auxsigma);
	mpf_clear(auxinter);
	mpf_clear(interdecfloat);
	mpf_clear(interkgfloat);
	mpf_clear(qfloat);
	mpf_clear(sqrtq);
	srand(time(NULL));



	/*gmp_printf("SigmaEnc: %.*Ff \n", 64,sigmaenc);
	gmp_printf("Sqrt(u): %.*Ff \n", 64,sqrtu);
	gmp_printf("SigmaKG: %.*Ff \n", 64,sigmakg);
	gmp_printf("InterDec: %Zd \n",interdec);
	gmp_printf("InterKG: %Zd \n",interkg);
	printf("\n");*/

	/*fmpz_t sample;
	fmpz_init(sample);
	disc_gauss_Zq(sigmakg,q,sample);
	printf("Sample: ");
	fmpz_print(sample);
	printf("\n");*/


	//Compute the matrix of t subsets of players
	int** matrixt = (int**)malloc(u * sizeof(int*));
	for (int index=0;index<u;++index){
	matrixt[index] = (int*)malloc(binomt * sizeof(int));
	for(int j=0; j<binomt;++j) matrixt[index][j]=0;
	}
	matrix(u,t,binomt,matrixt);
	/*printf("Matrix of subsets for KH:\n");
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomt; ++j) printf("%d ", matrixt[i][j]);
		printf("\n");
	}
	printf("\n");
	printf("\n");*/
	int binomut1 = binomial(u-1,u-t-1);
	int **allowedt = malloc(u*sizeof(int*));
	for(int i=0; i<u; ++i) {
		allowedt[i] = malloc(binomut1*sizeof(int));
		for(int j=0; j<binomut1; ++j) allowedt[i][j]=0;
	}
	for(int i=0; i<u; ++i) {
		int k=0;
		for(int j=0; j<binomt; ++j) {
			if(matrixt[i][j]==0) {
				allowedt[i][k]=j;
				k=k+1;
			}
		}
	}
	/*printf("Matrix of KH keys each player has:\n");
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomut1; ++j) printf("%d ", allowedt[i][j]);
		printf("\n");
	}
	printf("\n");
	printf("\n");*/


	//Compute the matrix of t+1 subsets of players
	int binomt1 = binomial(u,t+1);
	int** matrixt1 = (int**)malloc(u * sizeof(int*));
	for (int index=0;index<u;++index){
	matrixt1[index] = (int*)malloc(binomt1 * sizeof(int));
	for(int j=0; j<binomt1;++j) matrixt1[index][j]=0;
	}
	matrix(u,t+1,binomt1,matrixt1);
	/*printf("Matrix of allowed subsets to decrypt:\n");
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomt1; ++j) printf("%d ", matrixt1[i][j]);
		printf("\n");
	}
	printf("\n");
	printf("\n");*/
	int binomu1 = binomial(u-1,t);
	int** allowedt1 = (int**)malloc(u * sizeof(int*));
	for (int index=0;index<u;++index){
    allowedt1[index] = (int*)malloc(binomu1 * sizeof(int));
    for(int j=0; j<binomu1;++j) allowedt1[index][j]=0;
  }
	for(int i=0; i<u; ++i) {
		int k=0;
		for(int j=0; j<binomt1; ++j) {
			if(matrixt1[i][j]==1) {
				allowedt1[i][k]=j;
				k=k+1;
			}
		}
	}
	/*printf("Matrix of allowed subsets to decrypt:\n");
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomu1; ++j) printf("%d ", allowedt1[i][j]);
		printf("\n");
	}
	printf("\n");
	printf("\n");*/


	//Create the keys "map"
	int keys=binomt;
	int** key_map1 = (int**)malloc((u+keys) * sizeof(int*));
	for (int index=0;index<u+keys;++index){
		key_map1[index] = (int*)malloc(t * sizeof(int));
		for(int j=0; j<t;++j) key_map1[index][j]=0;
	}
	for(int j=0; j<t;++j) key_map1[0][j]=0;
	for(int j=0; j<t;++j) key_map1[1][j]=0;
	int* state = (int*)malloc(0 * sizeof(int));
	int* indexes = (int*)malloc(u * sizeof(int));
	for(int i=0; i<u;++i) indexes[i]=i+1;
	create_keys(state,indexes,t,key_map1,0,u,keys,t);
	free(state);
	free(indexes);


	//printf("Beginning of the for\n");
	// Simulation of Key Generation
	fmpz_poly_t lambda;
	fmpz_poly_init(lambda);
	//Set the argument of the PRF as 0,1,2,3,....
	for(int i=0; i<n;++i) fmpz_poly_set_coeff_si(lambda,i,i);
	fmpz_poly_t s;
	fmpz_poly_t aE;
	fmpz_poly_t bE;
	fmpz_t KH[keys];
	for(int i=0; i<keys; ++i) fmpz_init(KH[i]);
	fmpz_poly_t **sshares;
	sshares = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
	for(int i=0; i<binomt1; ++i) {
		sshares[i] = flint_malloc(u*sizeof(fmpz_poly_t));
		//for(int j=0; j<u; ++j) fmpz_poly_init(sshares[i][j]);
	}
	double **timeskg = (double**)malloc(5 * sizeof(double*));
	for (int index=0;index<5;++index){
		timeskg[index] = (double*)malloc(u * sizeof(double));
		for(int j=0; j<u;++j) timeskg[index][j]=0.0;
	}


	// Simulate the key generation repetitions times
	fmpz_poly_t m1, m2, uenc, v;
	double avgmin=0.0;
	double avgmax=0.0;
	for(int rep=0; rep<repetitions; ++rep) {
		// Initialize again all needed variables: s,aE,bE,KH,sshares,timeskg
		fmpz_poly_init(s);
		fmpz_poly_init(aE);
		fmpz_poly_init(bE);
		for(int i=0; i<binomt1; ++i) {
			for(int j=0; j<u; ++j) fmpz_poly_init(sshares[i][j]);
		}
		for (int index=0;index<5;++index){
			for(int j=0; j<u;++j) timeskg[index][j]=0.0;
		}

		// Simulate Key Generation
		keygen_sim(timeskg,sshares,aE,bE,KH,allowedt1,allowedt,lambda,matrixt1,key_map1,keys,sigmakg,binomu1,binomt1,u,n,t,q,interkg);

		// Recover s
		int players[t+1];
		int count = 0;
		for(int k=0; k<u; ++k) {
			if(matrixt1[k][0]==1) {
				players[count]=k+1;
				count=count+1;
			}
		}
		compute_shamir_Rq(s,sshares[0],players,t,u,n,q);

		// Verify several messages are correctly encrypted and decrypted
		fmpz_poly_init(m1);
		fmpz_poly_init(m2);
		fmpz_poly_init(uenc);
		fmpz_poly_init(v);
		for(int rep=0; rep<20; ++rep) {
			// Generate random message m1
			for(int i=0; i<n; ++i) {
				double random = rand_gen();
				if(random<0.5) fmpz_poly_set_coeff_ui(m1,i,0);
				else fmpz_poly_set_coeff_ui(m1,i,1);
			}
			//Encrypt message
			encrypt(m1,uenc,v,aE,bE,sigmaenc,n,q,s);

			// Decrypt message
			decrypt(m2,s,uenc,v,q,n);
			int compare_messages = fmpz_poly_equal(m1,m2);
			if(compare_messages==0) printf("ERROR: message incorrectly decrypted\n\n");
		}

		// Compute minimum and maximum time and add it to the Average
		for(int i = 0; i<5; ++i) {
			double min = 1000000000000000000.0;
			double max = 0.0;
			for(int j=0; j<u; ++j) {
				if(timeskg[i][j]<min) min=timeskg[i][j];
				if(timeskg[i][j]>max) max=timeskg[i][j];
			}
			avgmin=avgmin+min;
			avgmax=avgmax+max;
		}
		//printf("The maximum average time in Key Generation was %fms in iteration %d\n", avgmax*1000/(rep+1), rep+1);
		
		fmpz_poly_clear(m1);
		fmpz_poly_clear(m2);
		fmpz_poly_clear(uenc);
		fmpz_poly_clear(v);
		fmpz_poly_clear(s);
		fmpz_poly_clear(aE);
		fmpz_poly_clear(bE);
		for(int i=0; i<binomt1; ++i) {
			for(int j=0; j<u; ++j) fmpz_poly_clear(sshares[i][j]);
		}
	}

	// Compute the average and print it in miliseconds
	avgmin = avgmin/repetitions*1000;
	avgmax = avgmax/repetitions*1000;
	FILE *f = fopen("keygen.csv","a");
	fprintf(f,"%f\n",avgmax);
	fclose(f);
	//printf("The minimum average time in Key Generation was %fms\n", avgmin);
	//printf("The maximum average time in Key Generation was %fms\n", avgmax);


	// Free all storage
	mpz_clear(q);
	mpz_clear(qp);
	mpz_clear(interdec); 
	mpz_clear(interkg);
	mpf_clear(sigma);
	mpf_clear(sigmaenc);
	mpf_clear(sigmakg);
	for(int index=0; index<u; ++index) free(matrixt1[index]);
	free(matrixt1);
	for(int i=0; i<u; ++i) free(matrixt[i]);
	free(matrixt);
	for(int index=0; index<u; ++index) free(allowedt1[index]);
	free(allowedt1);
	for(int index=0; index<u; ++index) free(allowedt[index]);
	free(allowedt);
	for(int index=0; index<u+keys; ++index) free(key_map1[index]);
	free(key_map1);
	for(int i=0; i<keys; ++i) fmpz_clear(KH[i]);
	for(int i=0; i<binomt1; ++i) flint_free(sshares[i]);
	flint_free(sshares);
	fmpz_poly_clear(lambda);
	for (int index=0;index<5;++index) free(timeskg[index]);
	free(timeskg);
}
