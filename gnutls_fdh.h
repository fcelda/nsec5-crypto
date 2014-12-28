#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <nettle/nettle-meta.h>
#include <nettle/rsa.h>

/*!
 * Get size of Full Domain Hash result.
 */
size_t nettle_fdh_len(const struct rsa_public_key *key);

/*!
 * Compute Full Domain Hash.
 *
 * \param[in]  data      Input data.
 * \param[in]  data_len  Length of the input data.
 * \param[out] sign      Output buffer.
 * \param[in]  sign_len  Capacity of the output buffer.
 * \param[in]  pubkey    RSA public key.
 * \param[in]  privkey   RSA private key.
 * \param[in]  hash      Hash function.
 *
 * \return Size of the Full Domain Hash, zero on error.
 */
size_t nettle_fdh_sign(const uint8_t *data, size_t data_len,
		       uint8_t *sign, size_t sign_len,
		       const struct rsa_public_key *pubkey,
		       const struct rsa_private_key *privkey,
		       const struct nettle_hash *hash);

/*!
 * Verify Full Domain Hash.
 *
 * \param[in] data      Input data.
 * \param[in] data_len  Length of the input data.
 * \param[in] sign      Signature to verify.
 * \param[in] sign_len  Length of the signature.
 * \param[in] pubkey    RSA public key.
 * \param[in] hash      Hash function.
 *
 * \return True if the signature was validated successfully.
 */
bool nettle_fdh_verify(const uint8_t *data, size_t data_len,
		       const uint8_t *sign, size_t sign_len,
		       const struct rsa_public_key *pubkey,
		       const struct nettle_hash *hash);


size_t gnutls_fdh_len(gnutls_x509_privkey_t key);

size_t gnutls_fdh_sign(const uint8_t *data, size_t data_len,
		       uint8_t *sign, size_t sign_len,
		       gnutls_x509_privkey_t key,
		       gnutls_digest_algorithm_t digest);

bool gnutls_fdh_verify(const uint8_t *data, size_t data_len,
		       const uint8_t *sign, size_t sign_len,
		       gnutls_pubkey_t key,
		       gnutls_digest_algorithm_t digest);
