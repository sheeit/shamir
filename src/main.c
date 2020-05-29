#include "shamir_key.h"
#include "shamir.h"

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
	char *secret_str;
	size_t i;

	init();

	mpz_init_set_str(secret, "0x112233445566778899AABBCCDDEEFF", 0);

	if (skey_generate(&keys, secret, 2, num_keys) != 0) {
		clear();
		fputs("skey_generate failed.", stderr);
		return EXIT_FAILURE;
	}

	for (i = 0; i < num_keys; ++i) {
		printf("Key %zu: ", i);
		skey_print(keys[i]);
	}

	secret_str = shamir2_calculate_secret_str(keys);
	if (!secret_str) {
		fputs("shamir2_calculate_secret_str returned NULL\n", stderr);
	} else {
		printf("Secret 1 = %s\n", secret_str);
		free(secret_str);
	}
	secret_str = shamir2_calculate_secret_str2(keys + 2);
	if (!secret_str) {
		fputs("shamir2_calculate_secret_str returned NULL\n", stderr);
	} else {
		printf("Secret 2 = %s\n", secret_str);
		free(secret_str);
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
	void *const k = keys;
	/* Free the momory held by the random state variable */
	skey_randfree();
	mpz_clear(secret);
	if (!keys)
		return;
	while (*keys)
		skey_free(*keys++);
	free(k);
}
