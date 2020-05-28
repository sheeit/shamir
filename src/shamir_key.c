/* My includes */
#include "shamir_key.h"
#include "getrandom.h"

/* Standard C includes */
#include <assert.h> /* for assert() */
#include <stdlib.h> /* for EXIT_FAILURE */
#include <stdio.h> /* for perror() */

/* Third-party includes */
#include <gmp.h>     /* for gmp_*  */


/* My constants */
#define DEV_URANDOM "/dev/urandom"

/* My macros */
/* CEIL_DIV(a, b) = ceil(a / b) */
#define CEIL_DIV(a, b) (((((a) / (b)) * (b)) == (a)) \
		? ((a) / (b)) : (((a) / (b)) + 1))
/* BASE62_DIGIT(x) returns the ascii code of the digit x in base 62
 * (0 <= x < 62).
 * Example: BASE62_DIGIT(12) => 'C' */
#define BASE62_DIGIT(x) (\
	((x) < 10U) \
		? ('0' + (x)) \
		: ((x) < 36U) \
			? ('A' + (x) - 10) \
			: ((x) < 62U) \
				? ('a' + (x) - 36) \
				: '?')
/* HEX_DIGIT(x) returns the ascii code of the digit x in hexadecimal
 * (0 <= x < 16).
 * Example: HEX_DIGIT(12) => 'C' */
#define HEX_DIGIT(x) (((x) < 16U) ? BASE62_DIGIT(x) : '?')

/* Minimum value for the keys_req paramater of skey_generate */
static const short unsigned min_keys_req = 2;

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
	/* TODO: write this function */
}

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

	/* TODO: write this function */

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

	mpz_init(x);
	mpz_init(y);
	mpz_init(xprod);
	for (k_count = 0; k_count < num_keys; ++k_count) {
		mpz_urandomb(x, randstate, SKEY_COEFF_BITCNT);
		mpz_set(y, secret);
		mpz_set(xprod, x);
		for (c_count = 0; c_count < ncoeffs; ++c_count) {
			mpz_mul(xprod, xprod, x);
			mpz_addmul(y, xprod, coeffs[c_count]);
		}
		keys[k_count] = skey_init(x, y);
	}

	for (c_count = 0; c_count < ncoeffs; c_count++)
		mpz_clear(coeffs[c_count]);

	mpz_clears(x, y, xprod, NULL);
	*keys_ = keys;
	return 0;
}

/* Initialize and seed the random state variable (randstate) */
void skey_randinit(void)
{
	char *number = getrandom_str((size_t) SKEY_COEFF_BITCNT);
	mpz_t seed;

	if (mpz_init_set_str(seed, number, 0) == -1) {
		/* TODO: handle error */
	}

	/* FIXME: remove debug printf */
	gmp_printf("number = <%s>\nseed = %Zd = %#Zx\n", number, seed, seed);

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
	gmp_printf("ShamirKey[x=%Zd, y=%Zd]\n", key->x, key->y);
}
