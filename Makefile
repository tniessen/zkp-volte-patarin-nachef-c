.PHONY: test
test: zkp-test
	./zkp-test

.PHONY: memtest
memtest: zkp-test
	valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ./zkp-test

CFLAGS = -std=c99 -Wall -Wextra -pedantic -Werror -O3 -g -Iinclude $^ -lcrypto -lm

LIB_SOURCES = src/commitment.c src/protocol.c src/random.c src/params_3x3x3.c src/params_5x5x5.c src/params_s41.c
TEST_SOURCES = test/test.c

zkp-test: $(LIB_SOURCES) $(TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@

.PHONY: clean
clean:
	rm -f zkp-test
