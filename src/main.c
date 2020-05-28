#include "shamir_key.h"

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

void init(void);
void clear(void);


static mpz_t secret;
static shamir_key **keys;
static size_t num_keys = 5;

int main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
	size_t i;

	init();

	mpz_init_set_str(secret, "112233445566778899", 10);

	if (skey_generate(&keys, secret, 2, num_keys) != 0) {
		clear();
		fputs("skey_generate failed.", stderr);
		return EXIT_FAILURE;
	}

	for (i = 0; i < num_keys; ++i) {
		printf("Key %zu: ", i);
		skey_print(keys[i]);
	}

	clear();

	return EXIT_SUCCESS;
}

void init(void)
{
	/* Random state initialization */
	skey_randinit();
}
void clear(void)
{
	/* Free the momory held by the random state variable */
	skey_randfree();
	mpz_clear(secret);
	if (!keys)
		return;
	while (*keys)
		skey_free(*keys++);
}
