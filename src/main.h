#ifndef E83E48D9_697C_4182_9D23_A3C90333E250
#define E83E48D9_697C_4182_9D23_A3C90333E250

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


#endif /* E83E48D9_697C_4182_9D23_A3C90333E250 */
