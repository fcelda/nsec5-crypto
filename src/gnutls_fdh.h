#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

size_t gnutls_fdh_len(gnutls_x509_privkey_t key);

size_t gnutls_fdh_sign(const uint8_t *data, size_t data_len,
		       uint8_t *sign, size_t sign_len,
		       gnutls_x509_privkey_t key,
		       gnutls_digest_algorithm_t digest);

bool gnutls_fdh_verify(const uint8_t *data, size_t data_len,
		       const uint8_t *sign, size_t sign_len,
		       gnutls_pubkey_t key,
		       gnutls_digest_algorithm_t digest);
