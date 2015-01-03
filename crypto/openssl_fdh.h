#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

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
 * \param[in]  key       RSA private key.
 * \param[in]  hash      Hash function.
 *
 * \return Size of the Full Domain Hash, zero on error.
 */
size_t openssl_fdh_sign(const uint8_t *data, size_t data_len,
			uint8_t *sign, size_t sign_len,
			RSA *key, const EVP_MD *hash);

/*!
 * Verify Full Domain Hash.
 *
 * \param[in] data      Input data.
 * \param[in] data_len  Length of the input data.
 * \param[in] sign      Signature to verify.
 * \param[in] sign_len  Length of the signature.
 * \param[in] key       RSA public/private key.
 * \param[in] hash      Hash function.
 *
 * \return True if the signature was validated successfully.
 */
bool openssl_fdh_verify(const uint8_t *data, size_t data_len,
			const uint8_t *sign, size_t sign_len,
			RSA *key, const EVP_MD *hash);
