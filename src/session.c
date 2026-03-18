#include "nanossl.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * Session helpers
 * --------------------------------------------------------------------- */

NanoSSL_Session *nanossl_session_new(void)
{
    NanoSSL_Session *s = (NanoSSL_Session *)calloc(1, sizeof(NanoSSL_Session));
    if (s) {
        s->created_at = time(NULL);
        s->last_used  = s->created_at;
    }
    return s;
}

void nanossl_session_free(NanoSSL_Session *session)
{
    if (!session)
        return;
    /* Scrub secrets before freeing. */
    memset(session->master_secret, 0, NANOSSL_MASTER_SECRET_LEN);
    free(session);
}

/* -----------------------------------------------------------------------
 * Session cache
 * --------------------------------------------------------------------- */

int nanossl_session_cache_init(NanoSSL_SessionCache *cache, size_t max_sessions)
{
    if (!cache)
        return NANOSSL_ERR_INVAL;

    cache->head         = NULL;
    cache->count        = 0;
    cache->max_sessions = (max_sessions == 0)
                              ? NANOSSL_SESSION_CACHE_DEFAULT_MAX
                              : max_sessions;
    return NANOSSL_OK;
}

void nanossl_session_cache_free(NanoSSL_SessionCache *cache)
{
    NanoSSL_Session *cur, *next;
    if (!cache)
        return;

    cur = cache->head;
    while (cur) {
        next = cur->next;
        nanossl_session_free(cur);
        cur = next;
    }
    cache->head  = NULL;
    cache->count = 0;
}

int nanossl_session_cache_add(NanoSSL_SessionCache *cache,
                              NanoSSL_Session      *session)
{
    if (!cache || !session)
        return NANOSSL_ERR_INVAL;
    if (session->id_len == 0 || session->id_len > NANOSSL_SESSION_ID_LEN)
        return NANOSSL_ERR_INVAL;

    /* Evict the oldest entry (tail) when the cache is full. */
    if (cache->count >= cache->max_sessions && cache->head) {
        NanoSSL_Session *prev = NULL, *cur = cache->head;
        while (cur->next) {
            prev = cur;
            cur  = cur->next;
        }
        if (prev)
            prev->next = NULL;
        else
            cache->head = NULL;
        nanossl_session_free(cur);
        cache->count--;
    }

    session->next = cache->head;
    cache->head   = session;
    cache->count++;
    return NANOSSL_OK;
}

/*
 * nanossl_session_cache_lookup
 *
 * Searches the cache for a session whose ID matches the supplied bytes.
 * Both the length and the content of the ID must match exactly.
 *
 * FIX: The original implementation compared the *pointer* value of `id`
 * against `s->id` which can never be equal for a freshly looked-up ID
 * buffer, causing every lookup to return NULL ("session not found").
 * The correct comparison uses memcmp() on the actual bytes.
 */
NanoSSL_Session *nanossl_session_cache_lookup(NanoSSL_SessionCache *cache,
                                              const unsigned char  *id,
                                              size_t                id_len)
{
    NanoSSL_Session *s;

    if (!cache || !id || id_len == 0 || id_len > NANOSSL_SESSION_ID_LEN)
        return NULL;

    for (s = cache->head; s != NULL; s = s->next) {
        if (s->id_len == id_len &&
            memcmp(s->id, id, id_len) == 0) {   /* compare content, not pointer */
            s->last_used = time(NULL);
            return s;
        }
    }
    return NULL;
}

int nanossl_session_cache_remove(NanoSSL_SessionCache *cache,
                                 const unsigned char  *id,
                                 size_t                id_len)
{
    NanoSSL_Session *prev = NULL, *cur;

    if (!cache || !id || id_len == 0 || id_len > NANOSSL_SESSION_ID_LEN)
        return NANOSSL_ERR_INVAL;

    for (cur = cache->head; cur != NULL; prev = cur, cur = cur->next) {
        if (cur->id_len == id_len &&
            memcmp(cur->id, id, id_len) == 0) {
            if (prev)
                prev->next = cur->next;
            else
                cache->head = cur->next;
            nanossl_session_free(cur);
            cache->count--;
            return NANOSSL_OK;
        }
    }
    return NANOSSL_ERR_NOTFOUND;
}
