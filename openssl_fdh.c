#include "openssl_fdh.h"

#include <stdbool.h>
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

	size_t out_len = BN_num_bytes(key->n);

	// compute MGF1 mask, use the same size as RSA modulo

	uint8_t mask[out_len];
	if (PKCS1_MGF1(mask, out_len, data, data_len, hash) != 0) {
		return 0;
	}

	// clear the highest bit of the mask

	mask[0] &= 0x7f;

	// preform raw RSA signature

	int r = RSA_private_encrypt(out_len, mask, sign, key, RSA_NO_PADDING);
	if (r < 0) {
		return 0;
	}

	return r;
}

/*!
 * Compute Full Domain Hash.
 */
bool openssl_fdh_verify(const uint8_t *data, size_t data_len,
			uint8_t *sign, size_t sign_len,
			RSA *key, const EVP_MD *hash)
{
	if (!data || !key || !sign || !hash || sign_len < RSA_size(key)) {
		return 0;
	}

	// compute MGF1 mask, use the same size as RSA modulo

	size_t mask_len = BN_num_bytes(key->n);
	uint8_t mask[mask_len];
	if (PKCS1_MGF1(mask, mask_len, data, data_len, hash) != 0) {
		return 0;
	}

	// clear the highest bit of the mask

	mask[0] &= 0x7f;

	// preform raw RSA signature

	int r = -10;
//	int r = RSA_private_decrypt();
//	int r = RSA_private_encrypt(mask_len, mask, sign, key, RSA_NO_PADDING);
	if (r < 0) {
		return 0;
	}

	return r;
}
