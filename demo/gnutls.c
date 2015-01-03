#include "demo.h"
#include "gnutls_fdh.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <gnutls/abstract.h>
#include <gnutls/x509.h>

const char *demo_name(void)
{
	return "GnuTLS";
}

/*!
 * Lookup hash function by name.
 */
static const gnutls_digest_algorithm_t lookup_hash(const char *name)
{
	for (const gnutls_digest_algorithm_t *h = gnutls_digest_list(); h && *h; h++) {
		if (strcasecmp(name, gnutls_digest_get_name(*h)) == 0) {
			return *h;
		}
	}

	return 0;
}

/*!
 * Convert GnuTLS RSA private key to public key.
 */
static gnutls_pubkey_t pubkey_from_privkey(gnutls_x509_privkey_t x509)
{
	gnutls_privkey_t privkey = NULL;
	gnutls_privkey_init(&privkey);
	if (gnutls_privkey_import_x509(privkey, x509, 0) != 0) {
		gnutls_privkey_deinit(privkey);
		return NULL;
	}
	
	gnutls_pubkey_t pubkey = NULL;
	gnutls_pubkey_init(&pubkey);
	int r = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
	gnutls_privkey_deinit(privkey);
	if (r != 0) {
		gnutls_pubkey_deinit(pubkey);
		return NULL;
	}

	return pubkey;
}

static bool load_pem(const char *filename, gnutls_datum_t *result_ptr)
{
	FILE *file = fopen(filename, "r");
	if (!file) {
		return false;
	}

	bool success = false;
	gnutls_datum_t result = { 0 };

	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	if (size < 0) {
		goto failed;
	}
	fseek(file, 0, SEEK_SET);

	result.size = size;
	result.data = malloc(size);
	if (!result.data) {
		goto failed;
	}

	if (fread(result.data, result.size, 1, file) != 1) {
		free(result.data);
		goto failed;
	}

	*result_ptr = result;
	success = true;

failed:
	fclose(file);
	return success;
}

int demo(const char *filename, const char *hash_name,
	 const uint8_t *data, size_t data_len)
{
	gnutls_digest_algorithm_t hash = lookup_hash(hash_name);
	if (hash == 0) {
		error("Error retrieving hash function.");
		return 1;
	}

	gnutls_datum_t pem = { 0 };
	if (!load_pem(filename, &pem)) {
		error("Error reading key file content.");
		return 1;
	}
	
	gnutls_x509_privkey_t privkey = NULL;
	gnutls_x509_privkey_init(&privkey);
	int r = gnutls_x509_privkey_import(privkey, &pem, GNUTLS_X509_FMT_PEM);
	free(pem.data);
	if (r != 0) {
		error("Error loading private private key.");
		return 1;
	}

	if (gnutls_x509_privkey_get_pk_algorithm(privkey) != GNUTLS_PK_RSA) {
		error("Loaded key is not a RSA key.");
		gnutls_x509_privkey_deinit(privkey);
		return 1;
	}

	// sign data

	size_t sign_len = gnutls_fdh_len(privkey);
	uint8_t sign[sign_len];
	size_t written = gnutls_fdh_sign(data, data_len, sign, sign_len, privkey, hash);
	if (written != sign_len) {
		error("Error creating FDH signature.");
		return 1;
	}

	printf("signature: ");
	print_hex(sign, sign_len);

	// drop private part of the key and verify the signature

	gnutls_pubkey_t pubkey = pubkey_from_privkey(privkey);
	if (!pubkey) {
		error("Error converting private key to public key.");
		return 1;
	}

	bool valid = gnutls_fdh_verify(data, data_len, sign, sign_len, pubkey, hash);
	printf("valid: %s\n", valid ? "true" : "false");

	return valid ? 0 : 1;
}
