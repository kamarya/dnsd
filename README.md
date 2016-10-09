# DNSd

DNSd is a daemon a.k.a. service for Unix-like systems. It provides a local DNS backend complying (partially) with [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt) in order to forward the queries/answers to/from Google Public DNS over HTTPS.

> Google Public DNS offers DNSSEC-validating resolution over an encrypted HTTPS connection. DNS-over-HTTPS greatly enhances privacy and security between a client and a recursive resolver, and complements DNSSEC to provide end-to-end authenticated DNS lookups.
> -- <cite>[Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https)</cite>

## Highlights
 - Ultra lightweight (disk and memory footage).
 - Full functionality behind the web proxy out of the box.
 - Minimalistic implementation approach.
 - Highly configurable through a simple config. file.
 - A Self contained package that depends only on [libcurl](https://curl.haxx.se/libcurl/).
 - Suppoted records are **A**,**AAAA**,**CNAME**,**NS** and **MX**.

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


# License

This software is licensed under the GNU GPLv3 license.

The user of this software (including the source code and the binary form) must read and accept the terms and conditions of [Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https) over HTTPS before usage.
