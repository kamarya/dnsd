all:
	gcc src/dnssec.c -Iinc -g -Wall -lcurl -std=gnu99 -o dnsd
install:
	cp dnsd.conf /etc/dnsd.conf
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
