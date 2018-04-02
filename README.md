# DNSd

DNSd is a daemon a.k.a. service for Unix-like systems. It provides a local DNS backend complying (partially) with [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt) in order to forward the queries/answers to/from Google Public DNS over HTTPS.

> Google Public DNS offers DNSSEC-validating resolution over an encrypted HTTPS connection. DNS-over-HTTPS greatly enhances privacy and security between a client and a recursive resolver, and complements DNSSEC to provide end-to-end authenticated DNS lookups.
> -- <cite>[Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https)</cite>

### Highlights
 - Ultra lightweight (disk and memory footage).
 - Full functionality behind the web proxy out of the box.
 - Minimalistic implementation approach.
 - Highly configurable through a simple config. file.
 - A Self contained package that depends only on [libcurl](https://curl.haxx.se/libcurl/).
 - Supported records are **A**,**AAAA**,**CNAME**,**NS** and **MX**.

# Build and Install
Build the software by running the following commands in the terminal.
```
make
make install
```
You may run the service in the background (as a daemon) by setting the config file path as follows.
```
dnsd -f /etc/dnsd.conf
```
After the daemon is successfully loaded, the local DNS service is available on the regular DNS port 53.
If you are behind a web proxy server, you need to set its address and port in the configuration file.

If you would like to add DNSd as a service on your Linux machine, install the launcher (init and systemd) configuration files.
```
make linux-service
service dnsd start
```
For *systemd* you may need to run ```systemctl daemon-reload``` before starting the service.

For macOS systems install and launch the service as follows.
```
make macos-service
launchctl load -w /Library/LaunchDaemons/service.dnsd.plist
```
### Verification
You can verify wether the service is accessible through ```host -va github.com localhost```.
```
Trying "github.com"
Using domain server:
Name: localhost
Address: 127.0.0.1#53
Aliases:

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61907
;; flags: qr rd; QUERY: 1, ANSWER: 11, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;github.com.			IN	ANY

;; ANSWER SECTION:
github.com.		299	IN	A	192.30.253.112
github.com.		299	IN	A	192.30.253.113
github.com.		899	IN	NS	ns-1283.awsdns-32.org.
github.com.		899	IN	NS	ns-1707.awsdns-21.co.uk.
github.com.		899	IN	NS	ns-421.awsdns-52.com.
github.com.		899	IN	NS	ns-520.awsdns-01.net.
github.com.		3599	IN	MX	1 aspmx.l.google.com.
github.com.		3599	IN	MX	10 alt3.aspmx.l.google.com.
github.com.		3599	IN	MX	10 alt4.aspmx.l.google.com.
github.com.		3599	IN	MX	5 alt1.aspmx.l.google.com.
github.com.		3599	IN	MX	5 alt2.aspmx.l.google.com.

Received 390 bytes from 127.0.0.1#53 in 178 ms
```
# License

This software is licensed under the GNU GPLv3 license.

The user of this software (including the source code and the binary form) must read and accept the terms and conditions of [Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https) over HTTPS before usage.
