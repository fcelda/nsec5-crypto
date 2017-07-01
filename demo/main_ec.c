#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

/**
 * Get number of bytes that fit given number of bits.
 *
 * ceil(div(bits/8))
 */
static int bits_in_bytes(int bits)
{
	return (bits + 7) / 8;
}

/**
 * Encode unsigned integer on fixed width.
 */
static void bn2bin(const BIGNUM *num, uint8_t *buf, size_t size)
{
	size_t need = BN_num_bytes(num);
	assert(need <= size);

	size_t pad = size - need;
	if (pad > 0) {
		memset(buf, 0, pad);
	}

	int ret = BN_bn2bin(num, buf + pad);
	assert(ret == need);
}

/**
 * Try converting random string to EC point.
 *
 * @return EC point or NULL if the random string cannot be interpreted as an EC point.
 */
static EC_POINT *RS2ECP(const EC_GROUP *group, const uint8_t *data, size_t size)
{
	uint8_t buffer[size + 1];
	buffer[0] = 0x02;
	memcpy(buffer + 1, data, size);

	EC_POINT *point = EC_POINT_new(group);
	if (EC_POINT_oct2point(group, point, buffer, sizeof(buffer), NULL) == 1) {
		return point;
	} else {
		EC_POINT_clear_free(point);
		return NULL;
	}
}

/**
 * Convert hash value to an EC point.
 *
 * This implementation will work for any curve but execution is not time-constant.
 *
 * @return EC point or NULL in case of failure.
 */
static EC_POINT *ECVRF_hash_to_curve1(const EC_GROUP *group, const EC_POINT *pubkey, const uint8_t *data, size_t size)
{
	int degree = bits_in_bytes(EC_GROUP_get_degree(group));
	uint8_t _pubkey[degree + 1];
	if (EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_COMPRESSED, _pubkey, sizeof(_pubkey), NULL) != sizeof(_pubkey)) {
		return NULL;
	}

	EC_POINT *result = NULL;

	BIGNUM *cofactor = BN_new();
	if (EC_GROUP_get_cofactor(group, cofactor, NULL) != 1) {
		return NULL;
	}

	EVP_MD_CTX md;
	EVP_MD_CTX_init(&md);

	bool cofactor_positive = !BN_is_negative(cofactor) && !BN_is_zero(cofactor);

	for (int _counter = 0; result == NULL || EC_POINT_is_at_infinity(group, result); _counter++) {
		assert(_counter < 256);
		uint32_t counter = htonl(_counter);
		static_assert(sizeof(counter) == 4, "counter is 4-bit");

		uint8_t hash[EVP_MAX_MD_SIZE] = {0};
		unsigned hash_size = sizeof(hash);

		EVP_DigestInit_ex(&md, EVP_sha256(), NULL);
		EVP_DigestUpdate(&md, _pubkey, sizeof(_pubkey));
		EVP_DigestUpdate(&md, data, size);
		EVP_DigestUpdate(&md, &counter, sizeof(counter));
		if (EVP_DigestFinal_ex(&md, hash, &hash_size) != 1) {
			EC_POINT_clear_free(result);
			result = NULL;
			break;
		}

		result = RS2ECP(group, hash, hash_size);
		if (result != NULL && cofactor_positive) {
			EC_POINT *tmp = EC_POINT_new(group);
			if (EC_POINT_mul(group, tmp, NULL, result, cofactor, NULL) != 1) {
				EC_POINT_clear_free(tmp);
				EC_POINT_clear_free(result);
				result = NULL;
				break;
			}
			EC_POINT_clear_free(result);
			result = tmp;
		}
	}

	BN_clear_free(cofactor);
	EVP_MD_CTX_cleanup(&md);

	return result;
}

/**
 * Hash several EC points into an unsigned integer.
 */
static BIGNUM *ECVRF_hash_points(const EC_GROUP *group, const EC_POINT **points, size_t count)
{
	BIGNUM *result = NULL;

	EVP_MD_CTX md;
	EVP_MD_CTX_init(&md);
	EVP_DigestInit_ex(&md, EVP_sha256(), NULL);

	for (size_t i = 0; i < count; i++) {
		uint8_t buffer[33];
		if (EC_POINT_point2oct(group, points[i], POINT_CONVERSION_COMPRESSED, buffer, sizeof(buffer), NULL) != sizeof(buffer)) {
			goto fail;
		}
		EVP_DigestUpdate(&md, buffer, sizeof(buffer));
	}

	uint8_t hash[EVP_MAX_MD_SIZE] = {0};
	unsigned hash_size = sizeof(hash);
	if (EVP_DigestFinal_ex(&md, hash, &hash_size) != 1) {
		goto fail;
	}

	assert(hash_size >= 16);
	result = BN_bin2bn(hash, 16, NULL);
fail:
	EVP_MD_CTX_cleanup(&md);

	return result;
}

/**
 * Construct ECVRF proof.
 *
 * @param[in]  group
 * @param[in]  pubkey
 * @param[in]  privkey
 * @param[in]  data
 * @param[in]  size
 * @param[out] proof
 * @param[in]  proof_size
 */
static bool ECVRF_prove(
	const EC_GROUP *group, const EC_POINT *pubkey, const BIGNUM *privkey,
	const uint8_t *data, size_t size,
	uint8_t *proof, size_t proof_size)
{
	// TODO: check input constraints

	bool result = false;

	const EC_POINT *generator = EC_GROUP_get0_generator(group);
	assert(generator);

	EC_POINT *hash = NULL;
	EC_POINT *gamma = NULL;
	EC_POINT *g_k = NULL;
	EC_POINT *h_k = NULL;
	BIGNUM *order = NULL;
	BIGNUM *nonce = NULL;
	BIGNUM *c = NULL;
	BIGNUM *cx = NULL;
	BIGNUM *s = NULL;

	hash = ECVRF_hash_to_curve1(group, pubkey, data, size);
	if (!hash) {
		goto fail;
	}

	gamma = EC_POINT_new(group);
	if (EC_POINT_mul(group, gamma, NULL, hash, privkey, NULL) != 1) {
		goto fail;
	}

	// FIXME: is this prime order?
	order = BN_new();
	if (EC_GROUP_get_order(group, order, NULL) != 1) {
		goto fail;
	}

	nonce = BN_new();
	if (BN_rand_range(nonce, order) != 1) {
		goto fail;
	}

	g_k = EC_POINT_new(group);
	if (EC_POINT_mul(group, g_k, NULL, generator, nonce, NULL) != 1) {
		goto fail;
	}

	h_k = EC_POINT_new(group);
	if (EC_POINT_mul(group, h_k, NULL, hash, nonce, NULL) != 1) {
		goto fail;
	}

	const EC_POINT *points[] = { generator, hash, pubkey, gamma, g_k, h_k };
	c = ECVRF_hash_points(group, points, sizeof(points) / sizeof(EC_POINT *));
	if (!c) {
		goto fail;
	}

	cx = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (BN_mod_mul(cx, c, privkey, order, ctx) != 1) {
		BN_CTX_free(ctx);
		goto fail;
	}
	BN_CTX_free(ctx);

	s = BN_new();
	if (BN_mod_sub(s, nonce, cx, order, ctx) != 1) {
		goto fail;
	}

	// write result
	int wrote = EC_POINT_point2oct(group, gamma, POINT_CONVERSION_COMPRESSED, proof, 33, NULL);
	assert(wrote == 33);
	(void)wrote;
	bn2bin(c, proof + 33, 16);
	bn2bin(s, proof + 49, 32);

	result = true;
fail:
	EC_POINT_clear_free(hash);
	EC_POINT_clear_free(gamma);
	EC_POINT_clear_free(g_k);
	EC_POINT_clear_free(h_k);
	BN_clear_free(order);
	BN_clear_free(nonce);
	BN_clear_free(c);
	BN_clear_free(cx);
	BN_clear_free(s);

	return true;
}

static bool ECVRF_decode_proof(
	const EC_GROUP *group, const uint8_t *proof, size_t size,
	EC_POINT **gamma_ptr, BIGNUM **c_ptr, BIGNUM **s_ptr)
{
	if (size != 81) {
		return false;
	}

	size_t gamma_size = 33;
	size_t c_size = 16;
	size_t s_size = 32;
	assert(gamma_size + c_size + s_size == size);

	const uint8_t *gamma_raw = proof;
	const uint8_t *c_raw = gamma_raw + gamma_size;
	const uint8_t *s_raw = c_raw + c_size;
	assert(s_raw + s_size == proof + size);

	EC_POINT *gamma = EC_POINT_new(group);
	if (EC_POINT_oct2point(group, gamma, gamma_raw, gamma_size, NULL) != 1) {
		EC_POINT_clear_free(gamma);
		return false;
	}

	BIGNUM *c = BN_bin2bn(c_raw, c_size, NULL);
	if (!c) {
		EC_POINT_clear_free(gamma);
		return false;
	}

	BIGNUM *s = BN_bin2bn(s_raw, s_size, NULL);
	if (!s) {
		EC_POINT_clear_free(gamma);
		BN_clear_free(c);
		return false;
	}

	*gamma_ptr = gamma;
	*c_ptr = c;
	*s_ptr = s;

	return true;
}

/**
 * Compute r = p1^f1 + p2^f2
 */
static EC_POINT *ec_mul_two(const EC_GROUP *group, const EC_POINT *p1, const BIGNUM *f1, const EC_POINT *p2, const BIGNUM *f2)
{
	EC_POINT *result = EC_POINT_new(group);
	if (!result) {
		return NULL;
	}

	const EC_POINT *points[] = { p1, p2 };
	const BIGNUM *factors[] = { f1, f2 };
	if (EC_POINTs_mul(group, result, NULL, 2, points, factors, NULL) != 1) {
		EC_POINT_clear_free(result);
		return NULL;
	}

	return result;
}

static bool ECVRF_verify(
	const EC_GROUP *group, const EC_POINT *pubkey,
	const uint8_t *data, size_t size,
	const uint8_t *proof, size_t proof_size)
{
	bool valid = false;

	EC_POINT *gamma = NULL;
	EC_POINT *u = NULL;
	EC_POINT *v = NULL;
	BIGNUM *c = NULL;
	BIGNUM *s = NULL;
	BIGNUM *c2 = NULL;

	if (!ECVRF_decode_proof(group, proof, proof_size, &gamma, &c, &s)) {
		goto fail;
	}

	const EC_POINT *generator = EC_GROUP_get0_generator(group);
	assert(generator);

	EC_POINT *hash = ECVRF_hash_to_curve1(group, pubkey, data, size);
	assert(hash);

	u = ec_mul_two(group, pubkey, c, generator, s);
	if (!u) {
		goto fail;
	}

	v = ec_mul_two(group, gamma, c, hash, s);
	if (!u) {
		goto fail;
	}

	const EC_POINT *points[] = {generator, hash, pubkey, gamma, u, v};
	c2 = ECVRF_hash_points(group, points, sizeof(points) / sizeof(EC_POINT *));
	if (!c2) {
		goto fail;
	}

	valid = BN_cmp(c, c2) == 0;

fail:
	EC_POINT_clear_free(gamma);
	EC_POINT_clear_free(u);
	EC_POINT_clear_free(v);
	BN_clear_free(c);
	BN_clear_free(s);
	BN_clear_free(c2);

	return valid;
}

static void hex_dump(const uint8_t *data, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		bool last = i + 1 == size;
		printf("%02x%c", (unsigned int)data[i], last ? '\n' : ':');
	}
}

int main(int argc, char *argv[])
{
	static const uint8_t public[65] =
    		"\x04\xdb\x72\x4c\xdd\x2d\x65\xd9\x0d\xe9\x82\xd2\xc6\x94\x3d"
    		"\x66\x18\x85\x28\xc2\x84\x6b\x1f\xeb\x95\x8d\x25\xf5\xf1\xbb"
    		"\x2b\xc6\xbe\x16\xab\xce\xbe\x01\xd6\x31\xd3\x4e\x69\xfe\xeb"
    		"\x87\x49\x1e\x5d\xfd\x1a\x04\xf2\x71\x89\x78\x30\x26\xad\x50"
    		"\xcd\xcb\xec\x78\x7c";

	static const uint8_t private[33] =
		"\x00\xe3\xd3\x78\x92\x71\xe6\x30\x67\x3c\x10\x98\xe7\x67\x00"
		"\xc4\x13\xb0\xee\x9a\xd5\x2b\x6a\xe1\x71\x5c\x1e\x8d\x2e\xea"
		"\x9b\x2d\xe9";

	int result = EXIT_FAILURE;

	EC_GROUP *group = NULL;
	EC_POINT *pubkey = NULL;
	BIGNUM *privkey = NULL;

	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (!group) {
		fprintf(stderr, "failed to get curve\n");
		goto fail;
	}

	pubkey = EC_POINT_new(group);
	if (EC_POINT_oct2point(group, pubkey, public, sizeof(public), NULL) != 1) {
		fprintf(stderr, "failed to create public key\n");
		goto fail;
	}

	privkey = BN_bin2bn(private, sizeof(private), NULL);
	if (!privkey) {
		fprintf(stderr, "failed to create private key\n");
		goto fail;
	}

	static const uint8_t message[] = "hello world";
	uint8_t proof[81] = {0};

	if (!ECVRF_prove(group, pubkey, privkey, message, sizeof(message), proof, sizeof(proof))) {
		fprintf(stderr, "failed to create VRF proof\n");
		goto fail;
	}

	printf("message = ");
	hex_dump(message, sizeof(message));
	printf("proof = ");
	hex_dump(proof, sizeof(proof));

	bool valid = ECVRF_verify(group, pubkey, message, sizeof(message), proof, sizeof(proof));
	printf("valid = %s\n", valid ? "true" : "false");

	result = EXIT_SUCCESS;
fail:
	EC_POINT_clear_free(pubkey);
	BN_clear_free(privkey);
	EC_GROUP_free(group);

	return result;
}
