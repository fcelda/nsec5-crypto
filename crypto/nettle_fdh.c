#include "nettle_fdh.h"
#include "nettle_mgf.h"

#include <string.h>

#include <nettle/bignum.h>
#include <nettle/nettle-meta.h>
#include <nettle/rsa.h>

/*!
 * Get size of Full Domain Hash result.
 */
size_t nettle_fdh_len(const struct rsa_public_key *key)
{
	return key ? key->size : 0;
}

size_t nettle_fdh_sign(const uint8_t *data, size_t data_len,
		       uint8_t *sign, size_t sign_len,
		       const struct rsa_public_key *pubkey,
		       const struct rsa_private_key *privkey,
		       const struct nettle_hash *hash)
{
	if (!data || !pubkey || !privkey || !sign || !hash || sign_len < pubkey->size) {
		return 0;
	}

	size_t len = pubkey->size;

	// compute MGF1 mask, clear the highest bit

	uint8_t mask[len];
	mgf_nettle(mask, sizeof(mask), data, data_len, hash);
	mask[0] &= 0x7f;

	// preform raw RSA encryption

	mpz_t sign_mpz;
	nettle_mpz_init_set_str_256_u(sign_mpz, len, mask);
	mpz_powm(sign_mpz, sign_mpz, privkey->d, pubkey->n);
	nettle_mpz_get_str_256(len, sign, sign_mpz);
	mpz_clear(sign_mpz);

	return len;
}

/*!
 * Verify Full Domain Hash.
 */
bool nettle_fdh_verify(const uint8_t *data, size_t data_len,
		       const uint8_t *sign, size_t sign_len,
		       const struct rsa_public_key *pubkey,
		       const struct nettle_hash *hash)
{
	if (!data || !sign || !pubkey || !hash || sign_len != pubkey->size) {
		return false;
	}

	size_t len = pubkey->size;

	// compute MGF1 mask, clear the highest bit

	uint8_t mask[len];
	mgf_nettle(mask, len, data, data_len, hash);
	mask[0] &= 0x7f;

	// preform raw RSA decryption

	uint8_t decrypted[len];
	mpz_t decrypted_mpz;
	nettle_mpz_init_set_str_256_u(decrypted_mpz, sign_len, sign);
	mpz_powm(decrypted_mpz, decrypted_mpz, pubkey->e, pubkey->n);
	nettle_mpz_get_str_256(len, decrypted, decrypted_mpz);
	mpz_clear(decrypted_mpz);

	// compare the result

	return memcmp(decrypted, mask, len) == 0;
}
