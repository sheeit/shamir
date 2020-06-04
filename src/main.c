#include "main.h"
#include "shamir_key.h"
#include "shamir.h"

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <unistd.h> /* getopt */


static mpz_t secret;
static shamir_key **keys;
static size_t num_keys = 5;

int main(int argc, char *argv[])
{
	/*
	char *secret_str;
	size_t i;
	*/
	struct arg arg;

	parse_arguments(argc, argv, &arg);

	/*
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
	*/

	return EXIT_SUCCESS;
}

void parse_arguments(int argc, char *argv[], struct arg *arg)
{
	extern char *optarg;
	extern int optind, opterr, optopt;
	const char *optstring = ":g:d:hfs";
	int ch;
	char *endptr;

	arg->operation.operation = UNSPECIFIED_OP;
	arg->argument.type  = UNSPECIFIED_ARG;

	while ((ch = getopt(argc, argv, optstring)) != -1) {
		switch (ch) {

		/* Operations */

		case 'h': /* Show help */
			usage_exit(argv[0], EXIT_SUCCESS, NULL);
			break;

		case 'g': /* Generate */
			if (arg->operation.operation != UNSPECIFIED_OP)
				usage_exit(argv[0], EXIT_FAILURE, "You can only specify -g or -d once");
			arg->operation.operation = GENERATE;

			arg->operation.arg.genkeys.keys_req = (unsigned) strtol(optarg, &endptr, 10);
			if (endptr == optarg) {
				fprintf(stderr, "%s: -g: %s does not seem to be a valid number.\n\n",
					argv[0], optarg);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			if (arg->operation.arg.genkeys.keys_req < 2) {
				fprintf(stderr, "%s: -g: KEYS_REQ (%u) must be at least %u.\n\n",
					argv[0], arg->operation.arg.genkeys.keys_req, 2);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			if (*endptr != ',') {
				fprintf(stderr, "%s: -g: you must specify two numbers, separated by a comma:\n"
					"KEYS_REQ,N_KEYS.\n"
					"See below for an explanation of what they mean.\n\n",
					argv[0]);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}

			optarg = endptr + 1; /* Skip the ',' */
			arg->operation.arg.genkeys.n_keys = (unsigned) strtol(optarg, &endptr, 10);
			if (endptr == optarg) {
				fprintf(stderr, "%s: -g: %s does not seem to be a valid number.\n\n",
					argv[0], optarg);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			if (arg->operation.arg.genkeys.n_keys < arg->operation.arg.genkeys.keys_req) {
				fprintf(stderr, "%s: -g: N_KEYS (%u) must not be less than KEYS_REQ (%u).\n\n",
					argv[0],
					arg->operation.arg.genkeys.n_keys,
					arg->operation.arg.genkeys.keys_req);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			if (*endptr) {
				fprintf(stderr, "%s: -g: Garbage at the end of N_KEYS: %s.\n\n",
					argv[0], endptr);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}

			break;

		case 'd': /* Decrypt */
			if (arg->operation.operation != UNSPECIFIED_OP)
				usage_exit(argv[0], EXIT_FAILURE, "You can only specify -g or -d once");
			arg->operation.operation = DECRYPT;

			arg->operation.arg.n = (unsigned) strtol(optarg, &endptr, 10);
			if (endptr == optarg) {
				fprintf(stderr, "%s: -d: %s does not seem to be a valid number.\n\n",
					argv[0], optarg);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			if (arg->operation.arg.n < 2) {
				fprintf(stderr, "%s: -d: N_KEYS (%u) must not be less than %u.\n\n",
					argv[0], arg->operation.arg.n, 2);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			if (*endptr) {
				fprintf(stderr, "%s: -d: Garbage at the end of N_KEYS: %s.\n\n",
					argv[0], endptr);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}

			break;


		/* Input types */

		case 'f':
			if (arg->argument.type != UNSPECIFIED_ARG)
				usage_exit(argv[0], EXIT_FAILURE, "You can only specify -f or -s once");
			arg->argument.type  = FILENAME;
			break;

		case 's':
			if (arg->argument.type != UNSPECIFIED_ARG)
				usage_exit(argv[0], EXIT_FAILURE, "You can only specify -f or -s once");
			arg->argument.type  = STRING;
			break;


		/* Invalid options */

		case ':': /* Missing argument */
			fprintf(stderr, "%s: Error: The option `-%c' requires an argument.\n",
				argv[0], optopt);
			usage_exit(argv[0], EXIT_FAILURE, NULL);
			break;

		case '?': /* Unknown option */
			usage_exit(argv[0], EXIT_FAILURE, "Failed to parse arguments correctly");
			break;
		}
	}

	switch (arg->operation.operation) {
		case GENERATE:
			if (optind == argc)
				usage_exit(argv[0], EXIT_FAILURE, "-g needs an argument (the secret)");
			if (optind + 1 < argc)
				usage_exit(argv[0], EXIT_FAILURE, "-g needs only one argument (the secret)");
			arg->argument.value.secret = argv[optind];
			break;

		case DECRYPT:
			if (optind == argc)
				usage_exit(argv[0], EXIT_FAILURE, "-d needs arguments (the keys)");
			if (argc - optind != arg->operation.arg.n) {
				fprintf(stderr, "%s: -d: argument number mismatch. Expected %u, got %d.\n\n",
					argv[0], arg->operation.arg.n, argc - optind);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			arg->argument.value.keys = &argv[optind];
			break;

		case UNSPECIFIED_OP:
		default:
			usage_exit(argv[0], EXIT_FAILURE, "You must specify an operation (-g or -d)");
			break;
	}

	fputs("Printing argument parsing results:\n", stderr);
	fprintf(stderr, "Operation: %s.\n",
		arg->operation.operation == GENERATE ? "GENERATE" : "DECRYPT");

	fputs("Operation paramaters:\n", stderr);
	if (arg->operation.operation == GENERATE) {
		fprintf(stderr, "\tKEYS_REQ = %u.\n\tN_KEYS   = %u.\n",
			arg->operation.arg.genkeys.keys_req,
			arg->operation.arg.genkeys.n_keys);
	} else { /* DECRYPT */
		fprintf(stderr, "N_KEYS = %u\n", arg->operation.arg.n);
	}

	fprintf(stderr, "Input type: %s\n",
		arg->argument.type == FILENAME ? "FILENAME"
			: arg->argument.type == STRING ? "STRING"
			: "UNSPECIFIED_ARG (error)");

	fputs("Argument(s)\n", stderr);
	if (arg->operation.operation == GENERATE) {
		fprintf(stderr, "Argument (secret): <%s>.\n", arg->argument.value.secret);
	} else { /* DECRYPT */
		size_t i;
		for (i = 0; i < arg->operation.arg.n; ++i)
			fprintf(stderr, "Argument %lu: <%s>.\n",
				(long unsigned) i,
				arg->argument.value.keys[i]);
	}
}

void __attribute__((noreturn)) usage_exit(
	const char *progname,
	int code,
	const char *error)
{
	fprintf(code == EXIT_SUCCESS ? stdout : stderr,
		"%s%s%s"

		"USAGE: %s <OPERATION> <INPUT TYPE> [--] <ARGUMENT>\n"

		"\nOPERATION:\n"

		"\t-g KEYS_REQ,N_KEYS:\n"
		"\t\tGenerate N_KEYS keys for use in decrypting ARGUMENT, which is the secret.\n"
		"\t\tThe keys are generated such that at least KEYS_REQ keys are needed for the decryption.\n"

		"\t-d N_KEYS:\n"
		"\t\tUse the N_KEYS keys specified in the ARGUMENTs to decrypt the secret.\n"

		"\t-h:\n"
		"\t\tShow this help.\n"

		"\nINPUT TYPE:\n"

		"\t-f:\n"
		"\t\tRead input from the filename(s) specified in ARGUMENT\n"

		"\t-s:\n"
		"\t\tGet input from ARGUMENT as a string.\n"

		"\nThe characters -- may be used to terminate option parsing, and anything after \n"
		"is an ARGUMENT.\n"

		"\nARGUMENTs depend on the other options used. See above.\n",

		error ? "Error: " : "",
		error ? error : "",
		error ? ".\n\n" : "",

		progname);

	exit(code);
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
