#include "gnutls_fdh.h"
#include "gnutls_mgf.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <nettle/bignum.h>

#include <stdbool.h>
#include <stdio.h>
#include <gnutls/abstract.h>

static void cleanup_datum(gnutls_datum_t *datum)
{
	gnutls_free(datum->data);
}

#define auto_gnutls_datum_t gnutls_datum_t __attribute__((cleanup(cleanup_datum)))

/*!
 * Convert GnuTLS RSA private key into Nettle RSA key.
 */
static bool key_g2n(const gnutls_x509_privkey_t key,
		    struct rsa_public_key *public_key,
		    struct rsa_private_key *private_key)
{
	// export RSA parameters

	auto_gnutls_datum_t m = { 0 };
	auto_gnutls_datum_t e = { 0 };
	auto_gnutls_datum_t d = { 0 };
	auto_gnutls_datum_t p = { 0 };
	auto_gnutls_datum_t q = { 0 };

	int r = gnutls_x509_privkey_export_rsa_raw(key, &m, &e, &d, &p, &q, NULL);
	if (r != GNUTLS_E_SUCCESS) {
		return false;
	}

	// import into Nettle structs

	struct rsa_public_key pub = { 0 };
	struct rsa_private_key priv = { 0 };

	nettle_mpz_init_set_str_256_u(pub.n, m.size, m.data);
	nettle_mpz_init_set_str_256_u(pub.e, e.size, e.data);
	if (nettle_rsa_public_key_prepare(&pub) != 1) {
		nettle_rsa_public_key_clear(&pub);
		return false;
	}

	nettle_mpz_init_set_str_256_u(priv.d, d.size, d.data);
	nettle_mpz_init_set_str_256_u(priv.p, p.size, p.data);
	nettle_mpz_init_set_str_256_u(priv.q, q.size, q.data);
	if (nettle_rsa_private_key_prepare(&priv) != 1) {
		nettle_rsa_public_key_clear(&pub);
		nettle_rsa_private_key_clear(&priv);
		return false;
	}

	// assign the result

	*public_key = pub;
	*private_key = priv;

	return true;
}

/*!
 * Convert GnuTLS digest algorithm to Nettle hash abstraction.
 */
static const struct nettle_hash *hash_g2n(gnutls_digest_algorithm_t digest)
{
	switch (digest) {
	case GNUTLS_DIG_MD2:    return &nettle_md2;
	case GNUTLS_DIG_MD5:    return &nettle_md5;
	case GNUTLS_DIG_RMD160: return &nettle_ripemd160;
	case GNUTLS_DIG_SHA1:   return &nettle_sha1;
	case GNUTLS_DIG_SHA224: return &nettle_sha224;
	case GNUTLS_DIG_SHA256: return &nettle_sha256;
	case GNUTLS_DIG_SHA384: return &nettle_sha384;
	case GNUTLS_DIG_SHA512: return &nettle_sha512;
	default:
		return 0;
	};
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

	size_t out_len = pubkey->size;

	// compute MGF1 mask, use the same size as RSA modulo

	uint8_t mask[out_len];
	mgf_nettle(mask, out_len, data, data_len, &nettle_sha256);

	// clear the highest bit of the mask

	mask[0] &= 0x7f;

	// preform raw RSA signature

	mpz_t sign_mpz;
	nettle_mpz_init_set_str_256_u(sign_mpz, out_len, mask);
	mpz_powm(sign_mpz, sign_mpz, privkey->d, pubkey->n);
	nettle_mpz_get_str_256(out_len, sign, sign_mpz);
	mpz_clear(sign_mpz);

	return out_len;
}

size_t gnutls_fdh_len(gnutls_x509_privkey_t key)
{
	if (!key) {
		return 0;
	}

	unsigned int bits = 0;
	gnutls_x509_privkey_get_pk_algorithm2(key, &bits);
	assert(bits % 8 == 0);

	return bits / 8;
}

size_t gnutls_fdh_sign(const uint8_t *data, size_t data_len,
		       uint8_t *sign, size_t sign_len,
		       gnutls_x509_privkey_t key,
		       gnutls_digest_algorithm_t digest)
{
	struct rsa_public_key pubkey = { 0 };
	struct rsa_private_key privkey = { 0 };

	const struct nettle_hash *hash = hash_g2n(digest);
	if (!hash) {
		return 0;
	}

	if (!key_g2n(key, &pubkey, &privkey)) {
		return 0;
	}

	int r = nettle_fdh_sign(data, data_len, sign, sign_len, &pubkey, &privkey, hash);

	rsa_public_key_clear(&pubkey);
	rsa_private_key_clear(&privkey);

	return r;
}
