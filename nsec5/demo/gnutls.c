#include "demo.h"
#include "gnutls_fdh.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/abstract.h>
#include <gnutls/x509.h>

const char *demo_name(void)
{
	return "GnuTLS";
}

static const gnutls_digest_algorithm_t lookup_hash(const char *name)
{
	const gnutls_digest_algorithm_t *h_ptr;
	for (h_ptr = gnutls_digest_list(); h_ptr && *h_ptr; h_ptr++) {
		if (strcasecmp(name, gnutls_digest_get_name(*h_ptr)) == 0) {
			return *h_ptr;
		}
	}

	return 0;
}

static size_t file_size(FILE *file)
{
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);

	return size < 0 ? 0 : size;
}

static bool load_file(const char *filename, gnutls_datum_t *result_ptr)
{
	FILE *file = fopen(filename, "r");
	if (!file) {
		return false;
	}

	gnutls_datum_t result = { 0 };
	result.size = file_size(file);
	if (result.size == 0) {
		fclose(file);
		return false;
	}

	result.data = malloc(result.size);
	if (!result.data) {
		fclose(file);
		return false;
	}

	if (fread(result.data, result.size, 1, file) != 1) {
		free(result.data);
		fclose(file);
		return false;
	}

	fclose(file);
	*result_ptr = result;
	return true;
}

static gnutls_x509_privkey_t load_privkey(const char *filename)
{
	gnutls_datum_t pem = { 0 };
	if (!load_file(filename, &pem)) {
		return NULL;
	}

	gnutls_x509_privkey_t key = NULL;
	gnutls_x509_privkey_init(&key);
	int r = gnutls_x509_privkey_import(key, &pem, GNUTLS_X509_FMT_PEM);
	free(pem.data);
	if (r != 0) {
		return NULL;
	}

	if (gnutls_x509_privkey_get_pk_algorithm(key) != GNUTLS_PK_RSA) {
		// RSA key is required
		gnutls_x509_privkey_deinit(key);
		return NULL;
	}

	return key;
}

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

int demo(const char *filename, const char *hash_name,
	 const uint8_t *data, size_t data_len)
{
	gnutls_digest_algorithm_t hash = lookup_hash(hash_name);
	if (hash == 0) {
		error("Error retrieving hash function.");
		return 1;
	}

	gnutls_x509_privkey_t privkey = load_privkey(filename);
	if (!privkey) {
		error("Error loading private key.");
	}

	// sign data

	size_t sign_len = gnutls_fdh_len(privkey);
	uint8_t sign[sign_len];
	size_t written = gnutls_fdh_sign(data, data_len, sign, sign_len, privkey, hash);
	if (written != sign_len) {
		error("Error creating FDH signature.");
		gnutls_x509_privkey_deinit(privkey);
		return 1;
	}

	print_sign_result(sign, sign_len);

	// drop private part of the key and verify the signature

	gnutls_pubkey_t pubkey = pubkey_from_privkey(privkey);
	gnutls_x509_privkey_deinit(privkey);
	if (!pubkey) {
		error("Error converting private key to public key.");
		return 1;
	}

	bool valid = gnutls_fdh_verify(data, data_len, sign, sign_len, pubkey, hash);
	gnutls_pubkey_deinit(pubkey);

	print_verify_result(valid);

	return valid ? 0 : 1;
}
