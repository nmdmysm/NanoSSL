#ifndef NANOSSL_H
#define NANOSSL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define NANOSSL_SESSION_ID_LEN   32   /* bytes */
#define NANOSSL_MASTER_SECRET_LEN 48  /* bytes */
#define NANOSSL_SESSION_CACHE_DEFAULT_MAX 1024

/* Error codes */
#define NANOSSL_OK           0
#define NANOSSL_ERR_NOMEM   -1
#define NANOSSL_ERR_INVAL   -2
#define NANOSSL_ERR_NOTFOUND -3

/* -----------------------------------------------------------------------
 * Session
 * --------------------------------------------------------------------- */

typedef struct NanoSSL_Session {
    unsigned char        id[NANOSSL_SESSION_ID_LEN];
    size_t               id_len;
    unsigned char        master_secret[NANOSSL_MASTER_SECRET_LEN];
    uint16_t             cipher_suite;
    time_t               created_at;
    time_t               last_used;
    struct NanoSSL_Session *next;
} NanoSSL_Session;

/* -----------------------------------------------------------------------
 * Session cache
 * --------------------------------------------------------------------- */

typedef struct {
    NanoSSL_Session *head;
    size_t           count;
    size_t           max_sessions;
} NanoSSL_SessionCache;

/* Initialize a session cache.  max_sessions == 0 uses the default limit. */
int  nanossl_session_cache_init(NanoSSL_SessionCache *cache,
                                size_t max_sessions);

/* Release all sessions stored in the cache (does not free cache itself). */
void nanossl_session_cache_free(NanoSSL_SessionCache *cache);

/* Add a session to the cache.  Returns NANOSSL_OK on success. */
int  nanossl_session_cache_add(NanoSSL_SessionCache *cache,
                               NanoSSL_Session *session);

/*
 * Look up a session by its ID.
 *
 * Returns a pointer to the matching session, or NULL if not found.
 * The returned pointer is valid until the session is removed from the cache.
 */
NanoSSL_Session *nanossl_session_cache_lookup(NanoSSL_SessionCache *cache,
                                              const unsigned char  *id,
                                              size_t                id_len);

/* Remove a session from the cache and free it. */
int  nanossl_session_cache_remove(NanoSSL_SessionCache *cache,
                                  const unsigned char  *id,
                                  size_t                id_len);

/* -----------------------------------------------------------------------
 * Session helpers
 * --------------------------------------------------------------------- */

/* Allocate and zero-initialize a new session structure. */
NanoSSL_Session *nanossl_session_new(void);

/* Free a session allocated with nanossl_session_new(). */
void nanossl_session_free(NanoSSL_Session *session);

#ifdef __cplusplus
}
#endif

#endif /* NANOSSL_H */
