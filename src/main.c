#include "main.h"
#include "shamir_key.h"
#include "shamir.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strncmp */
#include <gmp.h>
#include <unistd.h> /* getopt */


static mpz_t secret;
static shamir_key **keys;

void (*(op_functions[]))(const struct arg *) = {
	NULL,
	generate_func,
	decrypt_func
};

int main(int argc, char *argv[])
{
	/*
	char *secret_str;
	size_t i;
	*/
	struct arg arg;

	parse_arguments(argc, argv, &arg);

	/* Call the function based on the type of operation */
	op_functions[arg.operation.operation](&arg);

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

	if (arg->operation.operation == UNSPECIFIED_OP)
		usage_exit(argv[0], EXIT_FAILURE, "You must specify an operation (-g or -d)");

	if (arg->argument.type == UNSPECIFIED_ARG)
		usage_exit(argv[0], EXIT_FAILURE, "You must specify an input type (-f or -s)");

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
			if ((unsigned) (argc - optind) != arg->operation.arg.n) {
				fprintf(stderr, "%s: -d: argument number mismatch. Expected %u, got %d.\n\n",
					argv[0], arg->operation.arg.n, argc - optind);
				usage_exit(argv[0], EXIT_FAILURE, NULL);
			}
			arg->argument.value.keys = (const char **) argv + optind;
			break;

		case UNSPECIFIED_OP: /* Can't happen */
		default:
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

	fprintf(stderr, "Input type: %s.\n",
		arg->argument.type == FILENAME ? "FILENAME" : "STRING");

	fputs("Argument(s)\n", stderr);
	if (arg->operation.operation == GENERATE) {
		fprintf(stderr, "Argument (secret): <%s>.\n",
			arg->argument.type == FILENAME
			&& strncmp(arg->argument.value.secret, "-", 2) == 0
				? "(STANDARD INPUT)"
				: arg->argument.value.secret);
	} else { /* DECRYPT */
		size_t i;
		for (i = 0; i < arg->operation.arg.n; ++i)
			fprintf(stderr, "Argument %lu: <%s>.\n",
				(long unsigned) i,
				arg->argument.value.keys[i]);
	}
	/* Separate argument parsing output from actual program output */
	fputc('\n', stderr);
}

void __attribute__((noreturn)) usage_exit(
	const char *progname,
	int code,
	const char *error)
{
	fprintf(code == EXIT_SUCCESS ? stdout : stderr,
		"%s%s%s"

		"USAGE: %s <OPERATION> <INPUT TYPE> [--] <ARGUMENT>\n",

		error ? "Error: " : "",
		error ? error : "",
		error ? ".\n\n" : "",
		progname);

	/* Broken up into multiple calls because ISO C90 compilers are only
	 * required to support 509 characters. (-Woverlength-strings) */

	fputs(
		"\nOPERATION:\n"

		"\t-g KEYS_REQ,N_KEYS:\n"
		"\t\tGenerate N_KEYS keys for use in decrypting ARGUMENT, which is the secret.\n"
		"\t\tThe keys are generated such that at least KEYS_REQ keys are needed for the decryption.\n"

		"\t-d N_KEYS:\n"
		"\t\tUse the N_KEYS keys specified in the ARGUMENTs to decrypt the secret.\n"

		"\t-h:\n"
		"\t\tShow this help.\n",

		stderr);

	fputs(
		"\nINPUT TYPE:\n"

		"\t-f:\n"
		"\t\tRead input from the filename(s) specified in ARGUMENT\n"
		"\t\tYou can specify the special argument \"-\" to mean standard input.\n"

		"\t-s:\n"
		"\t\tGet input from ARGUMENT as a string.\n",

		stderr);

	fputs(
		"\nThe characters -- may be used to terminate option parsing, and anything after \n"
		"is an ARGUMENT.\n"

		"\nARGUMENTs depend on the other options used. See above.\n",

		stderr);

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

void generate_func(const struct arg *arg)
{
	int ret;
	const shamir_key **k;

	if (arg->operation.operation != GENERATE)
		return;

	switch (arg->argument.type) {

	char *secret_str; /* Perfectly legal, according the Standard, */
	FILE *f;          /* so long as I don't try to initialize it. */

	case FILENAME:

		/* Accept the filename "-" to mean standard input */
		if (strncmp(arg->argument.value.secret, "-", 2) == 0) {
			f = stdin;
		} else {
			f = fopen(arg->argument.value.secret, "rb");
			if (!f) {
				fprintf(stderr, "Failed to open file %s.\n",
					arg->argument.value.secret);
				exit(EXIT_FAILURE);
			}
		}

		secret_str = hex_encode_file(f);

		if (f != stdin) {
			if (fclose(f) == EOF) {
				free(secret_str);
				fputs("flcose() returned EOF.\n", stderr);
				exit(EXIT_FAILURE);
			}
		}

		if (!secret_str) {
			fputs("hex_encode_file() returned NULL.\n", stderr);
			exit(EXIT_FAILURE);
		}

		if (mpz_init_set_str(secret, secret_str, 16) == -1) {
			fputs("mpz_init_set_str() returned -1.\n", stderr);
			fprintf(stderr, "secret_str = %s.\n", secret_str);
			free(secret_str);
			exit(EXIT_FAILURE);
		}

		free(secret_str);
		break;

	case STRING:
		ret = mpz_init_set_str(secret, arg->argument.value.secret, 0);
		if (ret == -1) {
			fputs("mpz_init_set_str() returned -1.\n", stderr);
			fprintf(stderr, "arg->argument.value.secret = %s.\n",
				arg->argument.value.secret);
			exit(EXIT_FAILURE);
		}

		break;

	default: /* Can't happen */
		exit(EXIT_FAILURE);
	}

	init();

	ret = skey_generate(
		&keys,
		secret,
		arg->operation.arg.genkeys.keys_req,
		arg->operation.arg.genkeys.n_keys);

	if (ret != 0) {
		clear();
		fputs("skey_generate failed.", stderr);
		exit(EXIT_FAILURE);
	}

	/* Print the generated keys */
	for (k = (const shamir_key **) keys; *k; k++)
		skey_print(*k);


	/* Remember to free stuff */
	clear();

}
void decrypt_func(const struct arg *arg)
{
	if (arg->operation.operation != DECRYPT)
		return;

	/* TODO: write me! */
}

/* Do a hexdump of f */
char *hex_encode_file(FILE *f)
{
	static const char *hex_chars = "0123456789ABCDEF";
	char buf[BUFSIZ];
	char *hexdump = NULL;
	size_t size = 0; /* The total size of hexdump */
	size_t r;        /* The number of bytes read into the buffer */

	while ((r = fread(buf, 1, sizeof buf, f)) > 0) {
		/* If r < sizeof buf then this is the last iteration,
		 * so allocate one extra byte to null-terminate the output
		 * string */
		const size_t new_size = size + 2 * r + (r < sizeof buf);
		char *hd = realloc(hexdump, new_size);
		size_t i;

		if (!hd) {
			/* No need to check if hexdump is NULL.
			 * ISO/IEC 9899:TC2 7.20.3.2-2 says so. */
			free(hexdump);
			return NULL;
		}
		hexdump = hd;
		hd = hexdump + size;
		size = new_size;

		for (i = 0; i < r; ++i) {
			*hd++ = hex_chars[(buf[i] & 0xf0) >> 4];
			*hd++ = hex_chars[buf[i] & 0x0f];
		}
	}

	/* Check for errors */
	if (ferror(f)) {
		free(hexdump); /* Ditto */
		return NULL;
	}

	if (hexdump)
		hexdump[size - 1] = '\0';

	return hexdump;
}
