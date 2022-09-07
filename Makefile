.PHONY: all
all:nyufile
nyufile: nyufile.c
	gcc -g -pedantic -std=gnu99 -O -Wall -Wextra -l crypto    nyufile.c   -o nyufile

.PHONY: clean
clean:
	rm -f *.o nyufile
