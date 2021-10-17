.PHONY: test
test: zkp-test
	./zkp-test

.PHONY: memtest
memtest: zkp-test
	valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ./zkp-test

CFLAGS = -std=c99 -Wall -Wextra -pedantic -Werror -O3 -g -Iinclude $^ -lcrypto -lm

LIB_SOURCES = src/commitment.c src/protocol.c src/random.c src/params_3x3x3.c src/params_5x5x5.c src/params_s41.c src/params_s41ast.c src/params_s43ast.c src/params_s53ast.c
TEST_SOURCES = test/test.c

LINT_JOBS := $(addprefix lint~,$(LIB_SOURCES) $(TEST_SOURCES))

.PHONY: lint ${LINT_JOBS}
lint: ${LINT_JOBS}

${LINT_JOBS}: lint~%:
	clang-tidy $* -- $(CFLAGS)

zkp-test: $(LIB_SOURCES) $(TEST_SOURCES)
	$(CC) $(CFLAGS) -o $@

.PHONY: demo
demo: demo/lib.wasm demo/sodium.js

demo/lib.wasm: $(LIB_SOURCES)
	clang -flto -O3 -Wall -Wextra -pedantic -Werror \
	  -Wno-unused-function \
	  --target=wasm32-unknown-wasi \
	  --sysroot wasi-sdk-12.0/share/wasi-sysroot/ \
	  -Wl,--export-all \
	  -Wl,--no-entry \
	  -nostartfiles \
	  -D__WASM__ \
	  -Iinclude \
	  -Wl,--lto-O3, \
	  -Wl,-z,stack-size=65536 \
	  -o $@ \
	  $^

demo/sodium.js:
	wget -O $@ 'https://raw.githubusercontent.com/jedisct1/libsodium.js/f68bf71c8554e9f1d60556d400e616acf578a073/dist/browsers-sumo/sodium.js'

.PHONY: format
format:
	clang-format -i include/*/* src/* test/*

.PHONY: check-format
check-format:
	clang-format --dry-run -Werror include/*/* src/* test/*

.PHONY: clean
clean:
	rm -f zkp-test demo/lib.wasm
