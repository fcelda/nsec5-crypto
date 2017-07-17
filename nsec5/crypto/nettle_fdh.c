#include "nettle_fdh.h"
#include "nettle_mgf.h"

#include <assert.h>
#include <string.h>

#include <nettle/bignum.h>
#include <nettle/nettle-meta.h>
#include <nettle/rsa.h>

/*!
 * Write mpz_t on fixed width, the empty low is filled with zero bytes.
 */
static void write_mpz(uint8_t *buffer, size_t buffer_len, const mpz_t value)
{
	assert(buffer);

	unsigned int value_len = nettle_mpz_sizeinbase_256_u(value);
	if (value_len > buffer_len) {
		return;
	}

	unsigned int zeroes = buffer_len - value_len;
	memset(buffer, 0, zeroes);
	nettle_mpz_get_str_256(value_len, buffer + zeroes, value);
}

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

	// compute MGF1 mask

	uint8_t mask[pubkey->size - 1];
	mgf_nettle(mask, sizeof(mask), data, data_len, hash);

	// preform raw RSA encryption

	mpz_t sign_mpz;
	nettle_mpz_init_set_str_256_u(sign_mpz, sizeof(mask), mask);
	mpz_powm(sign_mpz, sign_mpz, privkey->d, pubkey->n);
	write_mpz(sign, sign_len, sign_mpz);
	mpz_clear(sign_mpz);

	return sign_len;
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

	// compute MGF1 mask

	uint8_t mask[pubkey->size - 1];
	mgf_nettle(mask, sizeof(mask), data, data_len, hash);

	// preform raw RSA decryption

	uint8_t decrypted[sign_len];
	mpz_t decrypted_mpz;
	nettle_mpz_init_set_str_256_u(decrypted_mpz, sign_len, sign);
	mpz_powm(decrypted_mpz, decrypted_mpz, pubkey->e, pubkey->n);
	write_mpz(decrypted, sizeof(decrypted), decrypted_mpz);

	return (sizeof(mask) + 1) == sizeof(decrypted) && decrypted[0] == 0 &&
	       memcmp(decrypted + 1, mask, sizeof(mask)) == 0;
}
