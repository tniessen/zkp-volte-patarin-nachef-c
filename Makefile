.PHONY: test
test: volte-zkp-c
	./volte-zkp-c

volte-zkp-c: main.c
	$(CC) -std=c99 -Wall -Wextra -pedantic -Werror -O0 -g -o $@ $^ -lcrypto
