#pragma once

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdlib.h>

/*!
 * Get size of Full Domain Hash result.
 */
size_t openssl_fdh_len(RSA *key);

/*!
 * Compute Full Domain Hash.
 *
 * \param[in]  data      Input data.
 * \param[in]  data_len  Length of the input data.
 * \param[out] sign      Output buffer.
 * \param[in]  sign_len  Capacity of the output buffer.
 * \param[in]  key       RSA key.
 * \param[in]  hash      Hash function.
 *
 * \return Size of the Full Domain Hash, zero on error.
 */
size_t openssl_fdh_sign(const uint8_t *seed, size_t seed_len,
			uint8_t *sign, size_t sign_len,
			RSA *key, const EVP_MD *hash);
