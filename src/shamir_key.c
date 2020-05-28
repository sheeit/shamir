/* My includes */
#include "shamir_key.h"

/* Standard C includes */
#include <assert.h>  /* for assert() */
#include <limits.h>  /* for CHAR_BIT */
#include <stdio.h>   /* for perror() */
#include <stdlib.h>  /* for abort(), rand() */

/* POSIX includes */
#include <fcntl.h>   /* for open() */
#include <unistd.h>  /* for read() */

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
			? ('A' + (x)) \
			: ((x) < 62U) \
				? ('a' + (x)) \
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
int skey_generate(shamir_key **keys,
		const mpz_t secret,
		unsigned short keys_req,
		unsigned num_keys)
{
	assert(keys_req >= min_keys_req);
	assert(keys_req <= num_keys);
	/* TODO: write this function */
}

/* Initialize and seed the random state variable (randstate) */
void skey_randinit(void)
{
	const size_t rand_bits = 64;
	const size_t bufsize = CEIL_DIV(rand_bits, CHAR_BIT);
	char *buf = malloc(bufsize);
	char *number = malloc(rand_bits * 2 + 1);
	mpz_t seed;
	int urandom_fd;
	ssize_t bytes_read;
	size_t i;
	int flags = O_RDONLY;

	assert(buf != NULL);

#ifdef O_NOCTTY
	flags |= O_CTTY;
#endif
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	urandom_fd = open(DEV_URANDOM, flags);
	if (urandom_fd == -1) {
		perror("Failed to open " DEV_URANDOM);
		free(buf);
		abort();
	}

	bytes_read = read(urandom_fd, buf, bufsize);
	if (bytes_read == -1) {
		perror("read");
		free(buf);
		if (close(urandom_fd) == -1)
			perror("Failed to close " DEV_URANDOM);
		abort();
	}
	if (close(urandom_fd) == -1)
		perror("Failed to close " DEV_URANDOM);

	assert(bytes_read == bufsize);

	/* We have an array of size bufsize characters
	 * And we need to convert it to a string representing that number */
	for (i = 0; i < bufsize; ++i) {
		unsigned char c = buf[i];
		number[2 * i    ] = HEX_DIGIT((c & 0x10) >> 4);
		number[2 * i + 1] = HEX_DIGIT(c & 0x01);
	}
	free(buf);
	number[2 * i] = '\0';

	if (mpz_init_set_str(seed, number, 16) == -1) {
		/* TODO: handle error */
	}

	/* FIXME: remove debug printf */
	gmp_printf("number = <%s>\nseed = %Zd\n", number, seed);

	/* Choose one: */
	/* gmp_randinit_default(randstate); */
	/* gmp_randinit_mt(randstate); */
	assert(gmp_randinit_lc_2exp_size(randstate, (mp_bitcnt_t) rand_bits));

	/* Using time() to get a random numbe is not very good practice. */
	gmp_randseed(randstate, seed);

	mpz_clear(seed);
}

/* Free all memory occupied by the random state variable (randstate) */
void skey_randfree(void)
{
	gmp_randclear(randstate);
}
