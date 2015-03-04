#include "openssl_fdh.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

/*!
 * Get size of Full Domain Hash result.
 */
size_t openssl_fdh_len(RSA *key)
{
	if (!key) {
		return 0;
	}

	return RSA_size(key);
}

/*!
 * Compute Full Domain Hash.
 */
size_t openssl_fdh_sign(const uint8_t *data, size_t data_len,
			uint8_t *sign, size_t sign_len,
			RSA *key, const EVP_MD *hash)
{
	if (!data || !key || !sign || !hash || sign_len < RSA_size(key)) {
		return 0;
	}

	// compute MGF1 mask

	uint8_t mask[BN_num_bytes(key->n)];
	mask[0] = 0;
	if (PKCS1_MGF1(mask + 1, sizeof(mask) - 1, data, data_len, hash) != 0) {
		return 0;
	}

	// preform raw RSA signature

	int r = RSA_private_encrypt(sizeof(mask), mask, sign, key, RSA_NO_PADDING);
	if (r < 0) {
		return 0;
	}

	return r;
}

/*!
 * Verify Full Domain Hash.
 */
bool openssl_fdh_verify(const uint8_t *data, size_t data_len,
			const uint8_t *sign, size_t sign_len,
			RSA *key, const EVP_MD *hash)
{
	if (!data || !key || !sign || !hash || sign_len != RSA_size(key)) {
		return false;
	}

	// compute MGF1 mask

	uint8_t mask[BN_num_bytes(key->n)];
	mask[0] = 0;
	if (PKCS1_MGF1(mask + 1, sizeof(mask) - 1, data, data_len, hash) != 0) {
		return false;
	}

	// reverse RSA signature

	uint8_t decrypted[sign_len];
	int r = RSA_public_decrypt(sign_len, sign, decrypted, key, RSA_NO_PADDING);
	if (r < 0 || r != sign_len) {
		return false;
	}

	// compare the result

	return sizeof(mask) == sizeof(decrypted) &&
	       memcmp(mask, decrypted, sizeof(mask)) == 0;
}
