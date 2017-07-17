#include "demo.h"
#include "openssl_fdh.h"

#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

const char *demo_name(void)
{
	return "OpenSSL";
}

static RSA *load_privkey(const char *filename)
{
	FILE *pem = fopen(filename, "r");
	if (!pem) {
		return NULL;
	}

	RSA *key = PEM_read_RSAPrivateKey(pem, NULL, NULL, NULL);
	fclose(pem);

	return key;
}

static RSA *privkey_to_pubkey(RSA *privkey)
{
	RSA *pubkey = RSA_new();
	if (!pubkey) {
		return NULL;
	}

	pubkey->n = BN_dup(privkey->n);
	pubkey->e = BN_dup(privkey->e);

	return pubkey;
}

static void cleanup(void)
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

int demo(const char *filename, const char *hash_name,
	 const uint8_t *data, size_t data_len)
{
	atexit(cleanup);
	OpenSSL_add_all_digests();

	const EVP_MD *hash = EVP_get_digestbyname(hash_name);
	if (!hash) {
		error("Error retrieving hash function.");
		return 1;
	}

	RSA *privkey = load_privkey(filename);
	if (!privkey) {
		error("Error loading RSA private key.");
		return 1;
	}

	// sign data

	size_t sign_len = openssl_fdh_len(privkey);
	uint8_t sign[sign_len];
	size_t written = openssl_fdh_sign(data, data_len, sign, sign_len, privkey, hash);
	if (written != sign_len) {
		error("Error creating FDH signature.");
		RSA_free(privkey);
		return 1;
	}

	print_sign_result(sign, sign_len);

	// drop private part of the key and verify the signature

	RSA *pubkey = privkey_to_pubkey(privkey);
	RSA_free(privkey);
	if (!pubkey) {
		error("Error extracting public RSA parameters from the key.");
		return 1;
	}

	bool valid = openssl_fdh_verify(data, data_len, sign, sign_len, pubkey, hash);
	RSA_free(pubkey);

	print_verify_result(valid);

	return valid ? 0 : 1;
}
