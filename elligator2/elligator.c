static void elligator_fe64_A(fe64 out)
{
    out[0] = 486662;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
}

static void fe64_legendre(fe64 out, const fe64 z)
{
    fe64 t0;
    fe64 t1;
    fe64 t2;
    fe64 t3;
    int i;

    /*
     * Compute z ** ((p-1)/2) = z ** (2 ** 254 - 10) with the exponent as
     * 2 ** 254 - 10 = (2 ** 4) * (2 ** 250 - 1) + 6.
     */

    /* t0 = z ** 2 */
    fe64_sqr(t0, z);

    /* t3 = t0 * z = z ** 3 */
    fe64_mul(t3, t0, z);

    /* t0 = t3 ** 2 = z ** 6 -- stash t0 away for the end. */
    fe64_sqr(t0, t3);

    /* t1 = t0 * z = z ** 7 */
    fe64_mul(t1, t0, z);

    /* t2 = t1 ** 2 = z ** 14 */
    fe64_sqr(t2, t1);

    /* t2 = t2 ** 2 = z ** 28 */
    fe64_sqr(t2, t2);

    /* t1 = t3 * t2 = z ** 31 =  z ** (2 ** 5 - 1) */
    fe64_mul(t1, t3, t2);

    /* t2 = t1 ** (2 ** 5) = z ** ((2 ** 5) * (2 ** 5 - 1)) */
    fe64_sqr(t2, t1);
    for (i = 1; i < 5; ++i) {
        fe64_sqr(t2, t2);
    }

    /* t1 = t1 * t2 = z ** ((2 ** 5 + 1) * (2 ** 5 - 1)) = z ** (2 ** 10 - 1) */
    fe64_mul(t1, t2, t1);

    /* Continuing similarly... */

    /* t2 = z ** (2 ** 20 - 1) */
    fe64_sqr(t2, t1);
    for (i = 1; i < 10; ++i) {
        fe64_sqr(t2, t2);
    }
    fe64_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 40 - 1) */
    fe64_sqr(t3, t2);
    for (i = 1; i < 20; ++i) {
        fe64_sqr(t3, t3);
    }
    fe64_mul(t2, t3, t2);

    /* t2 = z ** (2 ** 10) * (2 ** 40 - 1) */
    for (i = 0; i < 10; ++i) {
        fe64_sqr(t2, t2);
    }
    /* t1 = z ** (2 ** 50 - 1) */
    fe64_mul(t1, t2, t1);

    /* t2 = z ** (2 ** 100 - 1) */
    fe64_sqr(t2, t1);
    for (i = 1; i < 50; ++i) {
        fe64_sqr(t2, t2);
    }
    fe64_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 200 - 1) */
    fe64_sqr(t3, t2);
    for (i = 1; i < 100; ++i) {
        fe64_sqr(t3, t3);
    }
    fe64_mul(t2, t3, t2);

    /* t2 = z ** ((2 ** 50) * (2 ** 200 - 1) */
    fe64_sqr(t2, t2);
    for (i = 1; i < 50; ++i) {
        fe64_sqr(t2, t2);
    }

    /* t1 = z ** (2 ** 250 - 1) */
    fe64_mul(t1, t2, t1);

    /* t1 = z ** ((2 ** 4) * (2 ** 250 - 1)) */
    fe64_sqr(t1, t1);
    for (i = 1; i < 4; ++i) {
        fe64_sqr(t1, t1);
    }

    /* Recall t0 = z ** 6; out = z ** (2 ** 254 - 10) */
    fe64_mul(out, t1, t0);
}

int elligator2_ed25519(const uint8_t *data, size_t size,
                       const uint8_t public_key[32],
                       uint8_t out_point[32])
{
    static const uint8_t SUITE[1] = {0x01};
    static const uint8_t ONE[1] = {0x01};

    // 3. hash(suite || one || pk || alpha)

    uint8_t hash[SHA512_DIGEST_LENGTH] = {0};
    SHA512_CTX hash_ctx;
    SHA512_Init(&hash_ctx);
    SHA512_Update(&hash_ctx, SUITE, sizeof(SUITE));
    SHA512_Update(&hash_ctx, ONE, sizeof(ONE));
    SHA512_Update(&hash_ctx, public_key, 32);
    SHA512_Update(&hash_ctx, data, size);
    SHA512_Final(hash, &hash_ctx);

    // 4. take first 32 bytes of the hash

    uint8_t truncatedHash[32] = {0};
    memcpy(truncatedHash, hash, 32);

    // 7. take highest order bit of truncated hash
    // 8. clear the bit in the source

    uint8_t x0 = truncatedHash[31] & 0x80;
    truncatedHash[31] &= 0x7f;

    // 9. convert to integer

    fe64 r = {0};
    fe64_frombytes(r, truncatedHash);

    // 10. u = - A / (1 + 2*(r^2) ) mod p

    fe64 t0 = {0};
    fe64 t1 = {0};

    fe64 one = {0};
    fe64_1(one);

    fe64 A = {0};
    elligator_fe64_A(A);

    fe64_sqr(t0, t0);       // r ** 2
    fe64_add(t0, t0, t0);   // 2 * (r ** 2)
    fe64_add(t0, one, t0);  // 1 + 2 * (r ** 2)
    fe64_invert(t0, t0);    // 1 / (1 + 2 * (r ** 2))

    fe64 u = {0};
    fe64_0(u);
    fe64_sub(u, u, A);      // -A
    fe64_mul(u, u, t0);     // -A / (1 / 2 * (r ** 2))

    // 11. w = u * (u^2 + A*u + 1) mod p

    fe64_sqr(t0, u);       // u ** 2
    fe64_mul(t1, A, u);    // A * u
    fe64_add(t0, t0, t1);  // u**2 + A*u
    fe64_add(t0, t0, one); // u**2 + A*u + 1

    fe64 w = {0};
    fe64_add(w, u, t0);    // u * (u**2 + A*u + 1)

    // 12. e = Legendre symbol of w and p

    fe64 e = {0};
    fe64_legendre(e, w);   // w ** ((p-1)/2)
    fe64_add(e, e, one);   // w ** ((p-1)/2) + 1

    fe64 u2 = {0};
    fe64_0(u2);
    fe64_sub(u2, u2, A);   // -A
    fe64_sub(u2, u2, u);   // -A - u

    unsigned b = e[0] >> 2;
    fe64_cswap(u, u2, b);  // swaps if b == 1

    fe64 uf = {0};
    fe64_copy(uf, u2);

    // 14. y coordinate

    fe64_sub(t0, uf, one); // t0 = uf - 1

    fe64_add(t1, uf, one); // t1 = uf + 1
    fe64_invert(t1, t1);   // t1 = 1 / (uf + 1)

    fe64 y = {0};
    fe64_mul(y, t0, t1);   // y = (uf - 1) / (uf + 1)

    // 15. encode point

    uint8_t h[32] = {0};
    fe64_tobytes(h, y);
    h[31] |= x0;

    // 17. hc = h ^ cofactor

    uint8_t cofactor[32] = {0};
    cofactor[0] = 8;
    x25519_scalar_mult(h, cofactor, out_point);

    return 0;
}
