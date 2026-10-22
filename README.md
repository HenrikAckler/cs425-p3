# IPv4 CIDR and Forwarding Table

## Design

IPv4 addresses are stored as `uint32_t` values in host byte order, with the
first dotted-quad octet in the most significant byte. The parsers validate
each decimal component directly and reject ambiguous leading zeros, invalid
octets, extra characters, and malformed prefixes.

Subnet calculations use a 32-bit mask. `/0` is handled explicitly to avoid a
32-bit shift by 32, and host counts use 64-bit arithmetic. `/31` has two usable
addresses and `/32` has one; for both, the first and last host values are the
network and broadcast values themselves.

The forwarding table stores a dynamically allocated array of routes. Lookup
scans every route and keeps the matching route with the greatest prefix
length, so route insertion order does not affect the result. The default
route works as a `/0` match and is selected only if no more specific route
matches.

## Known Bugs or Issues

No known issues.

## Experience

<!-- Add your project reflection here. -->
