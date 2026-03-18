CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Wpedantic -std=c99 -Iinclude

SRC     = src/session.c
OBJ     = $(SRC:.c=.o)

TEST_SRC  = tests/test_session.c
TEST_BIN  = tests/test_session

.PHONY: all tests clean

all: tests

tests: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) $(TEST_BIN)
