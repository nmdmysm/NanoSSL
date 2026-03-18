/*
 * test_session.c - unit tests for NanoSSL session cache
 *
 * Build:
 *   make tests
 *
 * Run:
 *   ./tests/test_session
 */

#include "nanossl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Minimal test harness
 * --------------------------------------------------------------------- */

static int g_tests_run    = 0;
static int g_tests_failed = 0;

#define ASSERT(cond, msg)                                            \
    do {                                                             \
        g_tests_run++;                                               \
        if (!(cond)) {                                               \
            fprintf(stderr, "FAIL [%s:%d] %s\n",                   \
                    __FILE__, __LINE__, (msg));                      \
            g_tests_failed++;                                        \
        } else {                                                     \
            printf("PASS %s\n", (msg));                              \
        }                                                            \
    } while (0)

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

static NanoSSL_Session *make_session(const unsigned char *id, size_t id_len)
{
    NanoSSL_Session *s = nanossl_session_new();
    if (!s) return NULL;
    memcpy(s->id, id, id_len);
    s->id_len = id_len;
    return s;
}

/* -----------------------------------------------------------------------
 * Tests
 * --------------------------------------------------------------------- */

static void test_lookup_finds_session(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id[NANOSSL_SESSION_ID_LEN];
    NanoSSL_Session *s, *found;

    memset(id, 0xAB, sizeof(id));

    nanossl_session_cache_init(&cache, 0);
    s = make_session(id, sizeof(id));
    nanossl_session_cache_add(&cache, s);

    /*
     * Lookup with a *separate* buffer containing the same bytes.
     * Before the fix this returned NULL because the pointer `id` inside
     * the session and the pointer passed to lookup were different.
     */
    found = nanossl_session_cache_lookup(&cache, id, sizeof(id));
    ASSERT(found != NULL, "lookup returns non-NULL for existing session");
    ASSERT(found == s,    "lookup returns the correct session pointer");

    nanossl_session_cache_free(&cache);
}

static void test_lookup_separate_buffer(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id_store[NANOSSL_SESSION_ID_LEN];
    unsigned char id_lookup[NANOSSL_SESSION_ID_LEN]; /* independent buffer */
    NanoSSL_Session *s, *found;

    memset(id_store,  0x55, sizeof(id_store));
    memset(id_lookup, 0x55, sizeof(id_lookup)); /* same content, different address */

    nanossl_session_cache_init(&cache, 0);
    s = make_session(id_store, sizeof(id_store));
    nanossl_session_cache_add(&cache, s);

    found = nanossl_session_cache_lookup(&cache, id_lookup, sizeof(id_lookup));
    ASSERT(found != NULL,
           "lookup with separate equal-content buffer finds session");

    nanossl_session_cache_free(&cache);
}

static void test_lookup_missing_session(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id_a[NANOSSL_SESSION_ID_LEN];
    unsigned char id_b[NANOSSL_SESSION_ID_LEN];
    NanoSSL_Session *s, *found;

    memset(id_a, 0x11, sizeof(id_a));
    memset(id_b, 0x22, sizeof(id_b));

    nanossl_session_cache_init(&cache, 0);
    s = make_session(id_a, sizeof(id_a));
    nanossl_session_cache_add(&cache, s);

    found = nanossl_session_cache_lookup(&cache, id_b, sizeof(id_b));
    ASSERT(found == NULL, "lookup returns NULL for absent session ID");

    nanossl_session_cache_free(&cache);
}

static void test_lookup_empty_cache(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id[NANOSSL_SESSION_ID_LEN];
    NanoSSL_Session *found;

    memset(id, 0xFF, sizeof(id));
    nanossl_session_cache_init(&cache, 0);

    found = nanossl_session_cache_lookup(&cache, id, sizeof(id));
    ASSERT(found == NULL, "lookup in empty cache returns NULL");

    nanossl_session_cache_free(&cache);
}

static void test_remove_session(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id[NANOSSL_SESSION_ID_LEN];
    NanoSSL_Session *s, *found;
    int rc;

    memset(id, 0x77, sizeof(id));

    nanossl_session_cache_init(&cache, 0);
    s = make_session(id, sizeof(id));
    nanossl_session_cache_add(&cache, s);

    rc = nanossl_session_cache_remove(&cache, id, sizeof(id));
    ASSERT(rc == NANOSSL_OK, "remove returns NANOSSL_OK");

    found = nanossl_session_cache_lookup(&cache, id, sizeof(id));
    ASSERT(found == NULL, "removed session is no longer found");
    ASSERT(cache.count == 0, "cache count is zero after remove");

    nanossl_session_cache_free(&cache);
}

static void test_multiple_sessions(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id1[NANOSSL_SESSION_ID_LEN];
    unsigned char id2[NANOSSL_SESSION_ID_LEN];
    unsigned char id3[NANOSSL_SESSION_ID_LEN];
    NanoSSL_Session *s1, *s2, *s3, *found;

    memset(id1, 0x01, sizeof(id1));
    memset(id2, 0x02, sizeof(id2));
    memset(id3, 0x03, sizeof(id3));

    nanossl_session_cache_init(&cache, 0);
    s1 = make_session(id1, sizeof(id1));
    s2 = make_session(id2, sizeof(id2));
    s3 = make_session(id3, sizeof(id3));

    nanossl_session_cache_add(&cache, s1);
    nanossl_session_cache_add(&cache, s2);
    nanossl_session_cache_add(&cache, s3);

    found = nanossl_session_cache_lookup(&cache, id1, sizeof(id1));
    ASSERT(found == s1, "first session found in multi-session cache");

    found = nanossl_session_cache_lookup(&cache, id2, sizeof(id2));
    ASSERT(found == s2, "second session found in multi-session cache");

    found = nanossl_session_cache_lookup(&cache, id3, sizeof(id3));
    ASSERT(found == s3, "third session found in multi-session cache");

    nanossl_session_cache_free(&cache);
}

static void test_partial_id_no_match(void)
{
    NanoSSL_SessionCache cache;
    unsigned char id_full[NANOSSL_SESSION_ID_LEN];
    NanoSSL_Session *s, *found;

    memset(id_full, 0xCC, sizeof(id_full));

    nanossl_session_cache_init(&cache, 0);
    s = make_session(id_full, sizeof(id_full));
    nanossl_session_cache_add(&cache, s);

    /* Search with a shorter length – must not match. */
    found = nanossl_session_cache_lookup(&cache, id_full, sizeof(id_full) - 1);
    ASSERT(found == NULL, "lookup with truncated ID length does not match");

    nanossl_session_cache_free(&cache);
}

/* -----------------------------------------------------------------------
 * Entry point
 * --------------------------------------------------------------------- */

int main(void)
{
    printf("=== NanoSSL session cache tests ===\n\n");

    test_lookup_finds_session();
    test_lookup_separate_buffer();
    test_lookup_missing_session();
    test_lookup_empty_cache();
    test_remove_session();
    test_multiple_sessions();
    test_partial_id_no_match();

    printf("\n%d tests run, %d failed.\n", g_tests_run, g_tests_failed);
    return g_tests_failed ? 1 : 0;
}
