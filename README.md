# DNSd

DNSd is a daemon i.e service for Unix-like systems. It provides a local DNS backend complying (partially) with [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt) in order to forward the queries/answers to/from Google Public DNS over HTTPS.

> Google Public DNS offers DNSSEC-validating resolution over an encrypted HTTPS connection. DNS-over-HTTPS greatly enhances privacy and security between a client and a recursive resolver, and complements DNSSEC to provide end-to-end authenticated DNS lookups.
> -- <cite>[Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https)</cite>

# License

This software is licensed under the GNU GPL license. The user(s) of this software must accept the terms and conditions of [Google Public DNS](https://developers.google.com/speed/public-dns/docs/dns-over-https) over HTTPS before usage.
