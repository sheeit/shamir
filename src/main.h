#ifndef E83E48D9_697C_4182_9D23_A3C90333E250
#define E83E48D9_697C_4182_9D23_A3C90333E250

#include <stdio.h> /* FILE */

enum operationtype {
	UNSPECIFIED_OP,
	GENERATE,
	DECRYPT
};
struct operation {
	enum operationtype operation;
	union {
		unsigned n; /* Number of keys required for decryption */
		struct {    /* Number of keys (and type) for generation */
			unsigned keys_req;
			unsigned n_keys;
		} genkeys;
	} arg;
};
enum argtype {
	UNSPECIFIED_ARG,
	FILENAME,
	STRING
};
/* TODO: STRING argtype should take an argument to specify wheher we should
 * pass the string as-is to mpz_init_set_str() or do a hexdump on it first. */
struct argument {
	enum argtype type; /* to tell us whether we're dealing with filenames
				or just plain strings */
	union {
		const char *secret; /* For generating */
		const char **keys;  /* For decrypting */
	} value;
};
struct arg {
	struct operation operation;
	struct argument  argument;
};

void parse_arguments(int argc, char *argv[], struct arg *arg);
void __attribute__((noreturn)) usage_exit(
	const char *progname,
	int code,
	const char *error);

void init(void);
void clear(void);

void generate_func(const struct arg *arg);
void decrypt_func(const struct arg *arg);

char *hex_encode_file(FILE *f);

extern void (*(op_functions[]))(const struct arg *);


#endif /* E83E48D9_697C_4182_9D23_A3C90333E250 */
