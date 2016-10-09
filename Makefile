all: dnssec.c
	gcc -g -Wall dnssec.c -lcurl -std=gnu99 -o dnsd
install:
	cp dnsd.conf /etc/dnsd.conf
	cp dnsd /usr/sbin/
