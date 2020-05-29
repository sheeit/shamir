#include "shamir.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gmp.h>

static char *get_str_secret(mpz_t *secret);

char *shamir2_calculate_secret_str(shamir_key **const keys)
{
	mpz_t ydiff, xdiff, b;

	/* f(x) = ax + b
	 *
	 * f(keys[0]->x) = keys[0]->y  <=>  a * keys[0]->x + b = keys[0]->y
	 *                             <=>  b = keys[0]->y - a * keys[0]->x              (1)
	 * f(keys[0]->x) = keys[0]->y  <=>  a * keys[1]->x + b = keys[1]->y
	 *                             <=>  b = keys[1]->y - a * keys[1]->x              (2)
	 *
	 * ydiff = keys[1]->y - keys[0]->y
	 * xdiff = keys[1]->x - keys[0]->x
	 *
	 * (1) and (2)  ==>  keys[0]->y - a * keys[0]->x = keys[1]->y - a * keys[1]->x
	 *              ==>  a * (keys[1]->x - keys[0]->x) = keys[1]->y - keys[0]->y
	 *              ==>  a = (keys[1]->y - keys[0]->y) / (keys[1]->x - keys[0]->x)   (3)
	 *              ==>  a = ydiff / xdiff                                           (4)
	 *
	 * (1) and (4)  ==>  b = keys[0]->y - keys[0]->x * ydiff / xdiff
	 * b is an integer, and so is keys[0]->y, this means that (keys[0]->x * ydiff) = 0 mod xdiff
	 * So we can do integer division directly.
	 */

	/* Initiate stuff */
	mpz_inits(xdiff, ydiff, b, NULL);

	/* Calculate xdiff */
	mpz_sub(xdiff, keys[1]->x, keys[0]->x);

	/* Calculate ydiff */
	mpz_sub(ydiff, keys[1]->y, keys[0]->y);

	/* Calculate keys[0]->x * ydiff */
	mpz_mul(b, keys[0]->x, ydiff);

	/* Make sure we can divide */
	assert(mpz_divisible_p(b, xdiff));

	/* Calculate keys[0]->x * ydiff / xdiff */
	mpz_divexact(b, b, xdiff);

	/* Negate keys[0]->x * ydiff / xdiff - keys[0]->y (which is -b) */
	mpz_sub(b, b, keys[0]->y);

	/* Calculate the final b (which is the secret) */
	mpz_neg(b, b);

	/* Clear no longer needed variables */
	mpz_clears(xdiff, ydiff, NULL);

	return get_str_secret(&b);
}

char *shamir2_calculate_secret_str2(shamir_key **const keys)
{
	mpz_t ydiff, xdiff, b;
	mpq_t a, a_times_k0x;

	/* f(x) = ax + b
	 *
	 * f(keys[0]->x) = keys[0]->y  <=>  a * keys[0]->x + b = keys[0]->y
	 *                             <=>  b = keys[0]->y - a * keys[0]->x              (1)
	 * f(keys[0]->x) = keys[0]->y  <=>  a * keys[1]->x + b = keys[1]->y
	 *                             <=>  b = keys[1]->y - a * keys[1]->x              (2)
	 *
	 * ydiff = keys[1]->y - keys[0]->y
	 * xdiff = keys[1]->x - keys[0]->x
	 *
	 * (1) and (2)  ==>  keys[0]->y - a * keys[0]->x = keys[1]->y - a * keys[1]->x
	 *              ==>  a * (keys[1]->x - keys[0]->x) = keys[1]->y - keys[0]->y
	 *              ==>  a = (keys[1]->y - keys[0]->y) / (keys[1]->x - keys[0]->x)   (3)
	 *              ==>  a = ydiff / xdiff                                           (4)
	 *
	 * (1) and (4)  ==>  b = keys[0]->y - keys[0]->x * ydiff / xdiff
	 * b is an integer, and so is keys[0]->y, this means that (keys[0]->x * ydiff) = 0 mod xdiff
	 * So we can do integer division directly.
	 */

	/* Initiate stuff */
	mpz_inits(xdiff, ydiff, b, NULL);

	/* Calculate xdiff */
	mpz_sub(xdiff, keys[1]->x, keys[0]->x);

	/* Calculate ydiff */
	mpz_sub(ydiff, keys[1]->y, keys[0]->y);

	/* Calculate a = ydiff / xdiff */
	mpq_init(a);
	mpq_set_num(a, ydiff);
	mpq_set_den(a, xdiff);
	mpq_canonicalize(a);

	/* Calculate a * keys[0]->x */
	mpq_init(a_times_k0x);
	mpq_set(a_times_k0x, a);
	mpz_mul(mpq_numref(a_times_k0x), mpq_numref(a_times_k0x), keys[0]->x);
	mpq_canonicalize(a_times_k0x);

	/* a * keys[0]->x must be an integer */
	assert(mpz_get_ui(mpq_denref(a_times_k0x)) == 1);

	/* Calculate b */
	mpz_sub(b, keys[0]->y, mpq_numref(a_times_k0x));

	/* Clear no longer needed variables */
	mpz_clears(xdiff, ydiff, NULL);
	mpq_clears(a, a_times_k0x, NULL);

	return get_str_secret(&b);
}

/* Note: after I finished writing this here function, I realized that I could have
 * done without it and used mpz_get_str().
 * But it's too late now.
 * I wrote it, and I damn well sure better use it. */
static char *get_str_secret(mpz_t *secret)
{
	static const char *const format = "%#Zx";
	char *str;
	size_t size;
	const int ret = gmp_snprintf(NULL, 0U, format, *secret);

	if (ret < 0)
		return NULL;

	size = (size_t) ret + 1;

	str = malloc(size);
	if (!str)
		return NULL;

	gmp_snprintf(str, size, format, *secret);

	/* Free the variable pointed to by secret */
	mpz_clear(*secret);

	return str;
}
