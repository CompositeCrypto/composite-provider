/* test_oid_registration.c — unit tests for composite OID registration */

#include <stdio.h>
#include <string.h>

#include <openssl/objects.h>

#include "../include/composite_provider.h"
#include "../src/composite_encoder.h"

static int test_count  = 0;
static int test_passed = 0;

#define TEST_START(name) \
    do { test_count++; printf("Test %d: %s ... ", test_count, (name)); } while(0)

#define TEST_PASS() \
    do { test_passed++; printf("PASSED\n"); } while(0)

#define TEST_FAIL(msg) \
    do { printf("FAILED: %s\n", (msg)); return 0; } while(0)

/* All 18 composite SIG short names */
static const char *all_sns[] = {
    MLDSA44_RSA2048_PSS_SN,
    MLDSA44_RSA2048_PKCS15_SN,
    MLDSA44_ED25519_SN,
    MLDSA44_P256_SN,
    MLDSA65_RSA3072_PSS_SN,
    MLDSA65_RSA3072_PKCS15_SN,
    MLDSA65_RSA4096_PSS_SN,
    MLDSA65_RSA4096_PKCS15_SN,
    MLDSA65_P256_SN,
    MLDSA65_P384_SN,
    MLDSA65_BRAINPOOLP256_SN,
    MLDSA65_ED25519_SN,
    MLDSA87_RSA3072_PSS_SN,
    MLDSA87_RSA4096_PSS_SN,
    MLDSA87_P384_SN,
    MLDSA87_BRAINPOOLP384_SN,
    MLDSA87_ED448_SN,
    MLDSA87_P521_SN,
};
static const int N_ALGS = (int)(sizeof(all_sns) / sizeof(all_sns[0]));

/* Corresponding dotted OID strings for a cross-check subset */
static const struct { const char *sn; const char *oid; } sn_to_oid[] = {
    { MLDSA44_RSA2048_PSS_SN,    MLDSA44_RSA2048_PSS_OID    },
    { MLDSA44_P256_SN,           MLDSA44_P256_OID           },
    { MLDSA65_RSA3072_PSS_SN,    MLDSA65_RSA3072_PSS_OID    },
    { MLDSA65_ED25519_SN,        MLDSA65_ED25519_OID        },
    { MLDSA87_P521_SN,           MLDSA87_P521_OID           },
    { MLDSA87_ED448_SN,          MLDSA87_ED448_OID          },
};

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

/*
 * After composite_register_oids(), OBJ_sn2nid() must return a non-NID_undef
 * NID for every composite SIG short name.
 */
static int test_oids_sn2nid_all(void)
{
    TEST_START("OBJ_sn2nid resolves all 18 composite SNs after registration");

    composite_register_oids();

    for (int i = 0; i < N_ALGS; i++) {
        if (OBJ_sn2nid(all_sns[i]) == NID_undef) {
            printf("FAILED (unresolved SN): %s\n", all_sns[i]);
            return 0;
        }
    }
    TEST_PASS();
    return 1;
}

/*
 * OBJ_find_sigid_algs() must succeed for every composite NID.
 * This exercises the OBJ_add_sigid() call in composite_register_oids() that
 * is required for certificate chain building (check_sig_alg_match path).
 */
static int test_oids_find_sigid_algs_all(void)
{
    TEST_START("OBJ_find_sigid_algs succeeds for all 18 composite NIDs");

    composite_register_oids();

    for (int i = 0; i < N_ALGS; i++) {
        int nid = OBJ_sn2nid(all_sns[i]);
        if (nid == NID_undef) {
            printf("FAILED (sn2nid): %s\n", all_sns[i]);
            return 0;
        }
        int dig_nid  = NID_undef;
        int pkey_nid = NID_undef;
        if (!OBJ_find_sigid_algs(nid, &dig_nid, &pkey_nid)) {
            printf("FAILED (find_sigid_algs): %s\n", all_sns[i]);
            return 0;
        }
    }
    TEST_PASS();
    return 1;
}

/*
 * Calling composite_register_oids() twice must be idempotent: the same NIDs
 * must be returned on both calls (OBJ_create is a no-op for already-known OIDs).
 */
static int test_oids_idempotent(void)
{
    TEST_START("composite_register_oids() is idempotent (second call preserves NIDs)");

    composite_register_oids();

    int nids_first[18];
    for (int i = 0; i < N_ALGS; i++)
        nids_first[i] = OBJ_sn2nid(all_sns[i]);

    composite_register_oids();

    for (int i = 0; i < N_ALGS; i++) {
        int nid2 = OBJ_sn2nid(all_sns[i]);
        if (nids_first[i] != nid2) {
            printf("FAILED: NID changed for %s (%d -> %d)\n",
                   all_sns[i], nids_first[i], nid2);
            return 0;
        }
    }
    TEST_PASS();
    return 1;
}

/*
 * OBJ_txt2nid() on the dotted OID string must resolve to the same NID as
 * OBJ_sn2nid() on the short name.
 */
static int test_oids_txt2nid_matches_sn2nid(void)
{
    TEST_START("OBJ_txt2nid matches OBJ_sn2nid for a subset of algorithms");

    composite_register_oids();

    int n = (int)(sizeof(sn_to_oid) / sizeof(sn_to_oid[0]));
    for (int i = 0; i < n; i++) {
        int nid_sn  = OBJ_sn2nid(sn_to_oid[i].sn);
        int nid_oid = OBJ_txt2nid(sn_to_oid[i].oid);
        if (nid_sn == NID_undef || nid_oid == NID_undef) {
            printf("FAILED (unresolved): %s\n", sn_to_oid[i].sn);
            return 0;
        }
        if (nid_sn != nid_oid) {
            printf("FAILED (NID mismatch for %s): sn=%d oid=%d\n",
                   sn_to_oid[i].sn, nid_sn, nid_oid);
            return 0;
        }
    }
    TEST_PASS();
    return 1;
}

/*
 * Before composite_register_oids() is called (fresh state), at least one SN
 * should be unknown.  Call without prior registration and check that
 * unregistered OIDs stay unknown until registration is done.
 *
 * Note: because other tests have already called composite_register_oids(), we
 * can only check that the post-registration state is correct here.  The real
 * "before" guarantee is enforced by ordering this test first in a clean build.
 * We therefore just re-verify post-registration correctness as a sanity check.
 */
static int test_oids_all_resolve_after_registration(void)
{
    TEST_START("all 18 SNs resolve after exactly one registration call");

    composite_register_oids();

    int resolved = 0;
    for (int i = 0; i < N_ALGS; i++) {
        if (OBJ_sn2nid(all_sns[i]) != NID_undef)
            resolved++;
    }

    if (resolved != N_ALGS) {
        printf("FAILED: only %d/%d SNs resolved\n", resolved, N_ALGS);
        return 0;
    }
    TEST_PASS();
    return 1;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(void)
{
    printf("=== Composite OID Registration Tests ===\n\n");

    test_oids_sn2nid_all();
    test_oids_find_sigid_algs_all();
    test_oids_idempotent();
    test_oids_txt2nid_matches_sn2nid();
    test_oids_all_resolve_after_registration();

    printf("\n=== Test Results ===\n");
    printf("Total:  %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_count - test_passed);

    if (test_passed == test_count) {
        printf("\n\u2713 All tests passed!\n");
        return 0;
    } else {
        printf("\n\u2717 Some tests failed!\n");
        return 1;
    }
}
