#include <stdio.h>
#include <gmp.h>


static int gcd(mpz_t res, mpz_t a, mpz_t b){
	mpz_t r;
	mpz_init(r);
	
	if (mpz_cmp(b,a) > 0) {	// b > a
		mpz_set(r,b);
		mpz_set(b,a);
		mpz_set(a,r);
		// r = b; b = a; a = r;
	}
	while (mpz_cmp_ui(b,0) > 0 ) {	// b > 0
		mpz_mod(r,a,b);	// r = a % b;
		mpz_set(a,b);	// a = b;
		mpz_set(b,r);	// b = r;
	}

	mpz_set(res,a);
	mpz_clear(r);
	return 0;
}



int main( int argc, char** argv ) {

	mpz_t n,m,t;

	mpz_inits(n,m,t,NULL);
	mpz_set_str(n,argv[1],10);
	mpz_set_str(m,argv[2],10);

	mpz_mul(t,n,m);

	printf("Tulos: ");
	mpz_out_str(stdout,10,t);
	printf("\nTulos hexana: 0x");
	mpz_out_str(stdout,16,t);
	printf("\ncalculating gcd: ");

	gcd(t,n,m);
	mpz_out_str(stdout,10,t);
	printf("\n");


	mpz_clears(n,m,t,NULL);
	return 0;
}
