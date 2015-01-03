#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nettle/nettle-meta.h>

#define MIN(a,b) \
	({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })

/*!
 * MGF1, Mask Generation Function based on a hash function.
 */
void mgf_nettle(uint8_t *mask, size_t mask_len,
		const uint8_t *seed, size_t seed_len,
		const struct nettle_hash *hash)
{
	if (!mask || !seed || !hash) {
		return;
	}

	uint8_t context[hash->context_size];
	uint8_t digest[hash->digest_size];

	for (size_t c = 0; mask_len > 0; c += 1) {
		uint8_t counter[4] = {
			(c >> 24) & 0xFF,
			(c >> 16) & 0xFF,
			(c >>  8) & 0xFF,
			(c >>  0) & 0xFF,
		};
		assert(c >> 32 == 0);

		hash->init(context);
		hash->update(context, seed_len, seed);
		hash->update(context, sizeof(counter), counter);
		hash->digest(context, sizeof(digest), digest);

		size_t copy = MIN(mask_len, sizeof(digest));
		memcpy(mask, digest, copy);
		mask += copy;
		mask_len -= copy;
	}
}
