/* My includes */
#include "shamir_key.h"
#include "getrandom.h"

/* Standard C includes */
#include <assert.h> /* for assert() */
#include <stdlib.h> /* for EXIT_FAILURE */
#include <stdio.h>  /* for perror() */

/* Third-party includes */
#include <gmp.h>    /* for gmp_*  */


/* Minimum value for the keys_req paramater of skey_generate */
static const short unsigned min_keys_req = 2;

/* Random state variable for GMP */
static gmp_randstate_t randstate;


/* Initialize a key. The key is basically two values: x and y
 * wher y = f(x).
 * f is a polynomial (whose coefficients are unknown to us) */
shamir_key *skey_init(const mpz_t x, const mpz_t y)
{
	shamir_key *key = malloc(sizeof *key);
	mpz_init_set(key->x, x);
	mpz_init_set(key->y, y);
	return key;
}

void skey_free(shamir_key *key)
{
	mpz_clears(key->x, key->y, NULL);
	free(key);
}


static void calculate_key(const mpz_t x, mpz_t y, mpz_t prod,
		const mpz_t a, mpz_t *c, size_t n);

/* Generate num_keys keys to give out to participants.
 * At least keys_req keys are needed to decrypt the secret.
 * Memory is allocated to hold the keys, and a pointer to the allocated memory
 * is stored in the variable pointed to by keys.
 * The user should remember to free it after use */
int skey_generate(shamir_key ***keys_,
		const mpz_t secret,
		unsigned short keys_req,
		unsigned num_keys)
{
	shamir_key **keys;
	mpz_t *coeffs, x, y, xprod;
	size_t ncoeffs = keys_req - 1;
	size_t c_count, k_count;

	assert(keys_req >= min_keys_req);
	assert(keys_req <= num_keys);

	/* Allocate one more for the terminating NULL */
	keys = malloc((num_keys + 1) * sizeof *keys);
	if (!keys) {
		perror("malloc");
		return EXIT_FAILURE;
	}
	keys[num_keys] = NULL;
	coeffs = malloc(ncoeffs * sizeof *coeffs);
	if (!coeffs) {
		perror("malloc");
		free(keys);
		return EXIT_FAILURE;
	}

	/* Initialize the coefficients */
	for (c_count = 0; c_count < ncoeffs; ++c_count) {
		mpz_init(coeffs[c_count]);
		mpz_urandomb(coeffs[c_count], randstate, SKEY_COEFF_BITCNT);
	}

	mpz_inits(x, y, xprod, NULL);

	for (k_count = 0; k_count < num_keys; ++k_count) {
		mpz_urandomb(x, randstate, SKEY_COEFF_BITCNT);

		/* Calculate y */
		calculate_key(x, y, xprod, secret, coeffs, ncoeffs);

		keys[k_count] = skey_init(x, y);
	}

	for (c_count = 0; c_count < ncoeffs; c_count++)
		mpz_clear(coeffs[c_count]);
	free(coeffs);

	mpz_clears(x, y, xprod, NULL);
	*keys_ = keys;
	return 0;
}

static void calculate_key(const mpz_t x, mpz_t y, mpz_t prod,
	const mpz_t a, mpz_t *c, size_t n)
{
	size_t i;

	/*            n
	 *           ____
	 *           \           i
	 * y  = a +   >   c  *  x
	 *           /___  i
	 *           i = 0
	 */

	/* Initialize the variable that will hold the product x * x * ... * x to x */
	mpz_set(prod, x);

	/* Initialze y to a */
	mpz_set(y, a);

	for (i = 0; i < n; ++i) {
		/* y += c[i] * prod */
		mpz_addmul(y, c[i], prod);
		/* Update the prouct */
		mpz_mul(prod, prod, x);
	}
}

/* Initialize and seed the random state variable (randstate) */
void skey_randinit(void)
{
	char *number = getrandom_str((size_t) SKEY_COEFF_BITCNT);
	mpz_t seed;

	if (mpz_init_set_str(seed, number, 0) == -1) {
		fputs("skey_randinit: mpz_init_set_str failed.\n", stderr);
		abort();
	}

	/* Choose one: */
	/* gmp_randinit_default(randstate); */
	/* gmp_randinit_mt(randstate); */
	assert(gmp_randinit_lc_2exp_size(randstate, 128));

	/* Using time() to get a random numbe is not very good practice. */
	gmp_randseed(randstate, seed);

	free(number);
	mpz_clear(seed);
}

/* Free all memory occupied by the random state variable (randstate) */
void skey_randfree(void)
{
	gmp_randclear(randstate);
}

void skey_print(const shamir_key *key)
{
	const int base = 62;
	char *const x = mpz_get_str(NULL, base, key->x);
	char *const y = mpz_get_str(NULL, base, key->y);

	printf("%s,%s\n", x, y);

	free(x);
	free(y);
}
