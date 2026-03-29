#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>

#include "xmss.h"
#include "params.h"
#include "delta_xmss.h"

#define XMSS_VARIANT "XMSS-SHA2_10_256"
#define TIMING_REPS 10000

/* Timing helpers */

static double elapsed_us(struct timespec start, struct timespec end)
{
    return (end.tv_sec - start.tv_sec) * 1e6
         + (end.tv_nsec - start.tv_nsec) / 1e3;
}

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Main */

int main(int argc, char *argv[])
{
    int num_sigs = 32;
    if (argc > 1) num_sigs = atoi(argv[1]);

    xmss_params params;
    uint32_t oid;

    if (xmss_str_to_oid(&oid, XMSS_VARIANT) < 0) {
        fprintf(stderr, "Unknown OID: %s\n", XMSS_VARIANT);
        return 1;
    }
    xmss_parse_oid(&params, oid);

    /* Memory sizes */
    unsigned long long cache_bytes = params.tree_height * params.n;

    printf("Delta-XMSS Benchmark\n");
    printf("  Variant      : %s\n",   XMSS_VARIANT);
    printf("  h'           : %u\n",   params.tree_height);
    printf("  n            : %u bytes\n", params.n);
    printf("  Cache size   : %llu bytes (fixed, A_idx stored at receiver)\n", cache_bytes);
    printf("  Full path    : %llu bytes (standard XMSS per signature)\n\n", cache_bytes);

    unsigned char *pk = malloc(XMSS_OID_LEN + params.pk_bytes);
    unsigned char *sk = malloc(XMSS_OID_LEN + params.sk_bytes);
    if (!pk || !sk) { perror("malloc"); return 1; }

    printf("Generating key pair...\n");
    xmss_keypair(pk, sk, oid);
    printf("Done.\n\n");

    unsigned long long mlen = 32;
    unsigned long long smlen;
    unsigned char m[32];
    memset(m, 0xAB, mlen);

    unsigned char *sm         = malloc(XMSS_OID_LEN + params.sig_bytes + mlen);
    unsigned char *cache      = malloc(cache_bytes);
    unsigned char *delta      = malloc(cache_bytes);
    unsigned char *auth_check = malloc(cache_bytes);
    unsigned char *cache_copy = malloc(cache_bytes);
    if (!sm || !cache || !delta || !auth_check || !cache_copy) { perror("malloc"); return 1; }

    /* Sign first message and initialise cache with A_0 */
    xmss_sign(sk, sm, &smlen, m, mlen);
    uint32_t prev_idx = delta_get_idx(&params, sm);
    memcpy(cache, delta_get_auth_path(&params, sm), cache_bytes);

    /* Accumulators */
    unsigned long long total_xmss    = 0;
    unsigned long long total_delta   = 0;
    double total_enc_us  = 0.0;
    double total_dec_us  = 0.0;
    uint64_t total_enc_cycles = 0;
    uint64_t total_dec_cycles = 0;
    int errors = 0;
    struct timespec t0, t1;
    uint64_t c0, c1;

    printf("%-6s %-4s %-10s %-10s %-8s %-8s %-10s %-10s %-6s\n",
           "idx", "nu", "XMSS(B)", "Delta(B)", "Enc(us)", "Dec(us)",
           "EncCycles", "DecCycles", "Match");
    printf("%-6s %-4s %-10s %-10s %-8s %-8s %-10s %-10s %-6s\n",
           "------","----","----------","----------","--------","--------",
           "----------","----------","------");

    for (int i = 1; i < num_sigs; i++) {
        xmss_sign(sk, sm, &smlen, m, mlen);
        uint32_t cur_idx = delta_get_idx(&params, sm);

        memcpy(auth_check, delta_get_auth_path(&params, sm), cache_bytes);

        unsigned int v    = delta_nu(prev_idx);
        unsigned int dlen = 0;

        /* Encode timing */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        c0 = rdtsc();
        for (int r = 0; r < TIMING_REPS; r++) {
            delta_encode(&params, delta, &dlen, sm, prev_idx);
        }
        c1 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double enc_us     = elapsed_us(t0, t1) / TIMING_REPS;
        uint64_t enc_cyc  = (c1 - c0) / TIMING_REPS;

        /* Decode timing */
        memcpy(cache_copy, cache, cache_bytes);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        c0 = rdtsc();
        for (int r = 0; r < TIMING_REPS; r++) {
            memcpy(cache, cache_copy, cache_bytes); /* reset cache */
            delta_decode(&params, cache, delta, prev_idx);
        }
        c1 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dec_us    = elapsed_us(t0, t1) / TIMING_REPS;
        uint64_t dec_cyc = (c1 - c0) / TIMING_REPS;

        /* Final decode for correctness check */
        memcpy(cache, cache_copy, cache_bytes);
        delta_decode(&params, cache, delta, prev_idx);

        int match = (memcmp(cache, auth_check, cache_bytes) == 0);
        if (!match) errors++;

        total_xmss       += cache_bytes;
        total_delta      += dlen;
        total_enc_us     += enc_us;
        total_dec_us     += dec_us;
        total_enc_cycles += enc_cyc;
        total_dec_cycles += dec_cyc;

        printf("%-6u %-4u %-10llu %-10u %-8.4f %-8.4f %-10" PRIu64 " %-10" PRIu64 " %-6s\n",
                prev_idx, v, cache_bytes, dlen,
                enc_us, dec_us, enc_cyc, dec_cyc,
                match ? "PASS" : "FAIL");

        prev_idx = cur_idx;
    }

    int n_trans = num_sigs - 1;
    double reduction = 100.0 * (1.0 - (double)total_delta / total_xmss);

    printf("\n=== Summary ===\n");
    printf("  Transitions      : %d\n",         n_trans);
    printf("  XMSS total       : %llu bytes\n", total_xmss);
    printf("  Delta total      : %llu bytes\n", total_delta);
    printf("  Cache size       : %llu bytes\n", cache_bytes);
    printf("  Reduction        : %.1f%%\n",     reduction);
    printf("  Avg encode       : %.4f us  |  %" PRIu64 " cycles\n",
            total_enc_us / n_trans, total_enc_cycles / n_trans);
    printf("  Avg decode       : %.4f us  |  %" PRIu64 " cycles\n",
            total_dec_us / n_trans, total_dec_cycles / n_trans);
    printf("  Errors           : %d\n",         errors);
    printf("\n%s\n", errors == 0 ? "All checks PASSED." : "Some checks FAILED.");

    free(pk); free(sk); free(sm); free(cache); free(cache_copy); free(delta); free(auth_check);
    return errors ? 1 : 0;
}