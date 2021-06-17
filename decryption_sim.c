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
*gcc decryption_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o decrypt.out -O2
*/



/*DONE********************************************
*Name: key_gen
*
*Description: generates private and public key of LPR cryptosystem and KH
*
*Arguments:   mpz_t aE[]: first part of public key
*             mpz_t bE[]: second part of public key
*             mpz_t s[]: secret key
*							fmpz_t KH[]: vector with all keys KH
*             mpf_t sigma: standard deviation of the discrete gaussian
*             int n: security parameter
*							int keys: number of keys
*             mpz_t q: modulo
***************************************************************/
void key_gen(fmpz_poly_t aE, fmpz_poly_t bE, fmpz_poly_t s, fmpz_t KH[],
	 						mpf_t sigma,int n,int keys, mpz_t q) {
	//Compute a random element in Zq for every key KH
	double rando;
	mpf_t r;
	mpf_t q2;
	mpf_t aux;
	mpz_t aux2;
	mpf_init(q2);
	mpf_set_z(q2,q);
	for(int i=0; i<keys; ++i) {
		mpf_init(r);
		mpf_init(aux);
		mpz_init(aux2);
		rando = rand_gen();
		mpf_set_d(r,rando);
		mpf_mul(aux,r,q2);
		round_mpf(aux2,aux);
		fmpz_set_mpz(KH[i],aux2);
		mpf_clear(r);
		mpf_clear(aux);
		mpz_clear(aux2);
	}
	mpf_clear(q2);

	// Choose s following the gaussian distribution
  disc_gauss_Rq(sigma,s,n,q);

  // Choose aE uniformly at random
  fmpz_poly_init(aE);
	rand_Rq(aE,n,q);

  //Compute bE
  fmpz_poly_t e;
  fmpz_poly_init(e);
  disc_gauss_Rq(sigma,e,n,q);
	fmpz_poly_t aux4;
	fmpz_poly_init(aux4);
	fmpz_poly_mul_Rq(aux4,aE,s,n,q);
  fmpz_poly_add(bE,aux4,e);
	fmpz_p_mod(bE,n,bE,q);
	fmpz_poly_clear(aux4);
	fmpz_poly_clear(e);
}

/*DONE******************************************************************
*Name: decrypt_sim
*
*Decription: Simulates the threshold decryption
*
*Arguments:
*************************************************************************/
void decrypt_sim(double **times, fmpz_poly_t **sshamirdec,
									fmpz_poly_t ***sshamirnoise, fmpz_poly_t **sshare,
									fmpz_poly_t uenc, fmpz_poly_t v, int** allowed,
									int** matrixt1, int **key_map1 ,fmpz_t KH[], int keys,
									int binomu1, int u, int n, int t, mpz_t q, mpz_t interdec) {
	// We have two steps per player: in the first we compute for every allowed
	// subset of players its additive share of the noise and compute the Shamir
	// shares for every player of it. In the second we compute v-sshare*u and add
	// for every allowed subset the corresponding Shamir shares

	// First step
	fmpz_poly_t lambda;
	fmpz_poly_init(lambda);
	fmpz_poly_add(lambda,uenc,v);
	fmpz_p_mod(lambda,n,lambda,q);

	fmpz_poly_t addnoiseshare;
	for(int i =0; i<u; ++i) {
		// Begin timer
		clock_t begin = clock();

		// We compute the additive share of every allowed subgroup
		for(int j=0; j<binomu1; ++j) {
			int column= allowed[i][j];
			fmpz_poly_init(addnoiseshare);

			//Compute the PRSS share of player i in the subset column
			int* state = (int*)malloc(u * sizeof(int));
			for(int k=0; k<u; ++k) state[k]=0;
			int order = 0;
			int found = 0;
			for(int k=0; k<u; ++k) {
				int mod = (column+k)%u;
				if(found == 0 && mod == i) found = 1;
				if(found ==0 && matrixt1[mod][column]==1) {
					state[order]=mod+1;
					order=order+1;
				}
			}

			int* indexes = (int*)malloc(u * sizeof(int));
			int count = 0;
			for(int k=1; k<u+1; ++k) {
				if(k!=i+1) {
					int found = 0;
					for(int l =0; l<order; ++l){
						if(state[l]==k) found =1;
					}
					if(found == 0) {
						indexes[count] = k;
						count=count+1;
					}
				}
			}

			PRSS_share(state,indexes,t-order,addnoiseshare,key_map1,KH,keys,order,u-(order+1),lambda,interdec,n);
			free(state);
			free(indexes);

			// Make a Shamir share between the t+1 players of the subset and store every
			// share in the big matrix
			gen_shamir_Rq(sshamirnoise[i][column],addnoiseshare,n,u,t,q);
		}

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[0][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}
	fmpz_poly_clear(addnoiseshare);
	fmpz_poly_clear(lambda);

	// Second step
	fmpz_poly_t auxdec;
	for(int i=0; i<u; ++i) {
		// Start timer
		clock_t begin = clock();

		// For every allowed subset of players we add all the shamir shares of the
		// noise
		for(int j=0; j<binomu1; ++j) {
			int column = allowed[i][j];
			
			// We compute v-sshare[i]*uenc
			fmpz_poly_init(auxdec);
			fmpz_poly_mul_Rq(auxdec,sshare[column][i],uenc,n,q);
			fmpz_poly_sub(auxdec,v,auxdec);
			//fmpz_p_mod(auxdec,n,auxdec,q);
			
			// Find the vector of players
			int players[t+1];
			int count = 0;
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][column]==1) {
					players[count]=k;
					count=count+1;
				}
			}
			// Compute the shamir share of the noise
			for(int k=0; k<t+1; ++k) {
				fmpz_poly_add(sshamirdec[column][i],sshamirdec[column][i],sshamirnoise[players[k]][column][i]);
			}
			// Add the auxdec
			fmpz_poly_add(sshamirdec[column][i],sshamirdec[column][i],auxdec);
			//fmpz_p_mod(sshamirdec[column][i],n,sshamirdec[column][i],q);
			fmpz_poly_clear(auxdec);
		}

		// End timer
		clock_t end = clock();

		// Compute time spent in player i
		times[1][i] = (double)(end-begin)/CLOCKS_PER_SEC;
	}
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

	//We set the general parameters sigmaenc,interdec and seed
	int binomt = binomial(u,t);
	mpz_t interdec;
	mpz_init(interdec);
	mpf_t sigma,sigmaenc,aux1,auxsigma,auxinter,qfloat,interdecfloat;
	mpf_init(sigma);
	mpf_init(sigmaenc);
	mpf_init(aux1);
	mpf_init(auxsigma);
	mpf_init(auxinter);
	mpf_init(qfloat);
	mpf_init(interdecfloat);
	
	mpf_set_z(qfloat,q);
	mpf_sqrt(aux1,qfloat);
	mpf_sqrt(auxinter,aux1);
	mpf_mul_ui(aux1,aux1,4*n);
	mpf_sub_ui(auxinter,auxinter,1);
	mpf_mul(auxinter,auxinter,qfloat);
	mpf_mul_ui(auxsigma,qfloat,2*n+1);
	mpf_mul(sigmaenc,aux1,auxsigma);
	mpf_ui_div(sigmaenc,1,sigmaenc);
	mpf_sqrt(sigmaenc,sigmaenc);
	mpf_mul_ui(interdecfloat,aux1,binomt);
	mpf_div(interdecfloat,auxinter,interdecfloat);
	mpz_set_f(interdec,interdecfloat);
	mpf_set_d(sigma,1.0);
	mpf_clear(aux1);
	mpf_clear(auxsigma);
	mpf_clear(auxinter);
	mpf_clear(interdecfloat);
	mpf_clear(qfloat);
	//mpf_clear(qfloat);
	srand(time(NULL));



	/*gmp_printf("SigmaEnc: %.*Ff \n", 64,sigmaenc);
	gmp_printf("InterDec: %Zd \n",interdec);
	printf("\n");*/


	//Compute the matrix of t subsets of players
	/*int** matrixt = (int**)malloc(u * sizeof(int*));
	for (int index=0;index<u;++index){
	matrixt[index] = (int*)malloc(binomt * sizeof(int));
	for(int j=0; j<binomt;++j) matrixt[index][j]=0;
	}
	matrix(u,t,binomt,matrixt);*/


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
	int** allowed = (int**)malloc(u * sizeof(int*));
	for (int index=0;index<u;++index){
    allowed[index] = (int*)malloc(binomu1 * sizeof(int));
    for(int j=0; j<binomu1;++j) allowed[index][j]=0;
  }
	for(int i=0; i<u; ++i) {
		int k=0;
		for(int j=0; j<binomt1; ++j) {
			if(matrixt1[i][j]==1) {
				allowed[i][k]=j;
				k=k+1;
			}
		}
	}
	/*printf("Matrix of allowed subsets to decrypt:\n");
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomu1; ++j) printf("%d ", allowed[i][j]);
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

	//Compute the keys
	fmpz_poly_t s;
	fmpz_poly_t aE;
	fmpz_poly_t bE;
	fmpz_poly_t ekg;
	fmpz_t KH[keys];

	fmpz_poly_init(s);
	fmpz_poly_init(aE);
	fmpz_poly_init(bE);
	//fmpz_poly_init(ekg);
	for(int i=0; i<keys; ++i) fmpz_init(KH[i]);

	key_gen(aE,bE,s,KH,sigmaenc,n,keys,q);

	// Create Shamir shares for every allowed subset to imitate KeyGen
	fmpz_poly_t **sshares;
	sshares = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
	for(int i=0; i<binomt1; ++i) {
		sshares[i] = flint_malloc(u*sizeof(fmpz_poly_t));
		for(int j=0; j<u; ++j) fmpz_poly_init(sshares[i][j]);
	}
	for(int i=0; i<binomt1; ++i) gen_shamir_Rq(sshares[i],s,n,u,t,q);



	// Simulation of decryption
	// Create the big matrix to store all the shares for every player sending,
	// every allowed subset of players and every player receiving
	fmpz_poly_t ***sshamirnoise;
	sshamirnoise = flint_malloc(u*sizeof(fmpz_poly_t**));
	for(int i=0; i<u; ++i) {
		sshamirnoise[i]= flint_malloc(binomt1*sizeof(fmpz_poly_t*));
		for(int j=0; j<binomt1; ++j) {
			sshamirnoise[i][j]=flint_malloc(u*sizeof(fmpz_poly_t));
			for(int k=0; k<u; ++k) fmpz_poly_init(sshamirnoise[i][j][k]);
		}
	}
	// Create matrix where every allowed subset of players will have their Shamir
	// shares
	fmpz_poly_t **sshamirdec;
	sshamirdec = flint_malloc(binomt1*sizeof(fmpz_poly_t*));
	for(int i=0; i<binomt1; ++i) {
		sshamirdec[i] = flint_malloc(u*sizeof(fmpz_poly_t));
		for(int j=0; j< u; ++j) fmpz_poly_init(sshamirdec[i][j]);
	}
	//Create time vector
	double **timesdec = (double**)malloc(2 * sizeof(double*));
	for (int index=0;index<2;++index){
    timesdec[index] = (double*)malloc(u * sizeof(double));
    for(int j=0; j<u;++j) timesdec[index][j]=0.0;
  }

	// Encrypt and decrypt 200 random messages, verify correctness and print average
	// maximum time and average minimum time
	fmpz_poly_t m1, m2, uenc, v, e[binomt1];
	double avgmin = 0.0;
	double avgmax = 0.0;
	int correctsim;
	for(int l=0; l<repetitions; ++l) {
		//Initialize all variables again: sshamirnoise, sshamirdec, times, m1, m2, uenc, v, e
		fmpz_poly_init(m1);
		fmpz_poly_init(m2);
		fmpz_poly_init(uenc);
		fmpz_poly_init(v);
		for(int i=0; i<u; ++i) {
			for(int j=0; j<binomt1; ++j) {
				for(int k=0; k<u; ++k) fmpz_poly_init(sshamirnoise[i][j][k]);
			}
		}
		for(int i=0; i<binomt1; ++i) {
			for(int j=0; j< u; ++j) fmpz_poly_init(sshamirdec[i][j]);
		}
		for(int index=0; index<2; ++index){
	    for(int j=0; j<u; ++j) timesdec[index][j]=0.0;
	  }
		for(int i=0; i<binomt1; ++i) fmpz_poly_init(e[i]);

		// Generate a random message m1
		for(int i=0; i<n; ++i) {
			double random = rand_gen();
			if(random<0.5) fmpz_poly_set_coeff_ui(m1,i,0);
			else fmpz_poly_set_coeff_ui(m1,i,1);
		}

		// Encrypt random message m1
		encrypt(m1,uenc,v,aE,bE,sigmaenc,n,q,s);

		// Decrypt random message
		decrypt_sim(timesdec,sshamirdec,sshamirnoise,sshares,uenc,v,allowed,matrixt1,key_map1,KH,keys,binomu1,u,n,t,q,interdec);

		// Compute the minimum and maximum time and add it to the average
		double min0 = 10000000000.0;
		double min1 = 10000000000.0;
		double max0 = 0.0;
		double max1 = 0.0;
		for(int i=0; i<u; ++i) {
			if(timesdec[0][i]<min0) min0=timesdec[0][i];
			if(timesdec[1][i]<min1) min1=timesdec[1][i];
			if(timesdec[0][i]>max0) max0=timesdec[0][i];
			if(timesdec[1][i]>max1) max1=timesdec[1][i];
		}
		avgmin=avgmin+min0+min1;
		avgmax=avgmax+max0+max1;

		// Verify that the threshold decryption is correct
		for(int i=0; i<binomt1; ++i) {
			// Find the vector of players
			int players[t+1];
			int count = 0;
			for(int k=0; k<u; ++k) {
				if(matrixt1[k][i]==1) {
					players[count]=k+1;
					count=count+1;
				}
			}
			compute_shamir_Rq(e[i],sshamirdec[i],players,t,u,n,q);
			fmpz_p_mod(e[i],n,e[i],q);
			round_message(e[i],m2,q,n);
		 	correctsim = fmpz_poly_equal(m1,m2);
		}
		int compare=1;
		for(int i=0; i<binomt1; ++i) {
			int compaux = fmpz_poly_equal(e[0],e[i]);
			if (compaux==0) compare =0;
		}

		// Print whether the the threshold decryption is correct or not
		//printf("Returns 1 if all the threshold decryptions are equal, 0 otherwise: %d\n", compare);
		//printf("Returns 1 if the threshold decryption is correct, 0 otherwise: %d\n", correctsim);
		
		fmpz_poly_clear(m1);
		fmpz_poly_clear(m2);
		fmpz_poly_clear(uenc);
		fmpz_poly_clear(v);
		for(int i=0; i<u; ++i) {
			for(int j=0; j<binomt1; ++j) {
				for(int k=0; k<u; ++k) fmpz_poly_clear(sshamirnoise[i][j][k]);
			}
		}
		for(int i=0; i<binomt1; ++i) {
			for(int j=0; j< u; ++j) fmpz_poly_clear(sshamirdec[i][j]);
		}
		for(int i=0; i<binomt1; ++i) fmpz_poly_clear(e[i]);
	}

	// Compute the average times in miliseconds and print them
	avgmin = avgmin/repetitions*1000;
	avgmax = avgmax/repetitions*1000;
	FILE *f = fopen("decrypt.csv","a");
	fprintf(f,"%f\n",avgmax);
	fclose(f);
	//printf("Average minimum decryption time: %f\n", avgmin);
	//printf("Average maximum decryption time: %f\n", avgmax);


	// Free all storage
	mpz_clear(q);
	mpz_clear(qp);
	mpz_clear(interdec);
	mpf_clear(sigma);
	mpf_clear(sigmaenc);
	for(int index=0; index<u; ++index) free(matrixt1[index]);
	for(int index=0; index<u; ++index) free(allowed[index]);
	for(int index=0; index<u+keys; ++index) free(key_map1[index]);
	free(key_map1);
	fmpz_poly_clear(s);
	fmpz_poly_clear(aE);
	//fmpz_poly_clear(bE);
	for(int i=0; i<keys; ++i) fmpz_clear(KH[i]);
	for(int i=0; i<binomt1; ++i) flint_free(sshares[i]);
	for(int i=0; i<u; ++i) {
		for(int j=0; j<binomt1; ++j) {
			flint_free(sshamirnoise[i][j]);
		}
	}
	for(int i=0; i<binomt1; ++i) flint_free(sshamirdec[i]);
	for (int index=0;index<2;++index) free(timesdec[index]);

}
