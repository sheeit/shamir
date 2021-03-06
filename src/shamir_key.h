#ifndef _8bb948bb_5c69_4aab_8f99_e2785279370a
#define _8bb948bb_5c69_4aab_8f99_e2785279370a

#include <gmp.h>


/* The bitcount of the coefficients used to generate the keys */
#define SKEY_COEFF_BITCNT ((mp_bitcnt_t) 256U)

struct shamir_key {
	mpz_t x;
	mpz_t y;
};
typedef struct shamir_key shamir_key;

shamir_key *skey_init(const mpz_t x, const mpz_t y);
void skey_free(shamir_key *key);
int skey_generate(shamir_key ***keys,
		const mpz_t secret,
		unsigned short keys_req,
		unsigned num_keys);
void skey_randinit(void);
void skey_randfree(void);
void skey_print(const shamir_key *key);

#endif /* !_8bb948bb_5c69_4aab_8f99_e2785279370a */

