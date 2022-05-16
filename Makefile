all:
	$(CC) src/dnssec.c -Iinc -Wall -lcurl -std=gnu11 -o dnsd
install:
	mkdir -p /etc/dnsd
	cp dnsd.conf /etc/dnsd/dnsd.conf
	cp google.der /etc/dnsd/google.der
	cp dnsd /usr/local/bin/
linux-service:
	cp service/dnsd.service /lib/systemd/system/
	chmod 644 /lib/systemd/system/dnsd.service
	cp service/dnsd /etc/init.d/
	chmod 755 /etc/init.d/dnsd
macos-service:
	cp service/service.dnsd.plist /Library/LaunchDaemons
clean:
	rm -f dnsd
