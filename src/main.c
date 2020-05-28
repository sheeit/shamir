#include "shamir_key.h"

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

void init(void);

int main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
	printf("Hello world!\n");
	init();

	return 0;
}

void init(void)
{
	/* Random state initialization */
	skey_randinit();

	/* Free the momory held by the random state variable */
	skey_randfree();
}
