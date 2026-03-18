# NanoSSL

A minimal, embedded-friendly SSL/TLS session-cache library written in C99.

## The "session not found" bug

The classic root cause of a session never being located in the cache is
comparing **pointers** instead of **content**:

```c
/* WRONG – compares the address of the caller's buffer, not its bytes */
if (s->id == id) { ... }

/* CORRECT – compares the actual session-ID bytes */
if (s->id_len == id_len && memcmp(s->id, id, id_len) == 0) { ... }
```

Every TLS client sends its session ID in a freshly allocated buffer, so a
pointer comparison will never match the copy stored inside the cache entry.
`memcmp` on the bytes is the only correct approach.

## Building

```sh
make tests          # compile and link the test binary
./tests/test_session  # run all tests
```

Requires a C99-capable compiler (GCC, Clang, …).

## Files

| Path | Description |
|------|-------------|
| `include/nanossl.h` | Public API – types, constants, function declarations |
| `src/session.c` | Session cache implementation |
| `tests/test_session.c` | Unit tests for the session cache |
| `Makefile` | Build rules |
