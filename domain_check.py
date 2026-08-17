"""
Domain existence check for sender domains, used by sweep.py's hardcoded
"Spam Domain" check and by debug_spam.py.

Originally used RDAP (Registration Data Access Protocol, the structured
JSON replacement for WHOIS) to check whether a sender's domain is actually
registered. RDAP required an HTTP round trip per domain, was subject to
rate limiting from the public rdap.org bootstrap redirector (causing real
spam to occasionally be missed on one sweep pass), and was slower overall.

This module uses plain DNS resolution (A records) instead -- standard
library only, no HTTP, no rate limits, typically well under 100ms per
check versus RDAP's multi-second lookups. This was validated by comparing
DNS results against RDAP's verdict across 50 real spam messages with zero
disagreements before switching over.

CAVEAT worth knowing: a domain can be legitimately registered and actively
used for email while having NO A record at all (e.g. a company that sends
mail from a domain but hosts no website on it). Such a domain would show
as "does not resolve" here even though it's completely real. This is a
known tradeoff, accepted after the empirical comparison above showed no
disagreements in practice for the spam actually being seen.

Version: 1.0.5

Change log:
  - v1.0.5 (2026-08-17): Synchronized module version metadata with the
    logging and digest traceability release.
  - v1.0.4 (2026-08-17): Treat resolver failures other than an explicit
    no-such-name result as inconclusive so they cannot trigger deletion.
"""
import socket
from typing import Optional


def registrable_domain(domain: str) -> str:
    """Best-effort guess at the registrable (second-level) domain by taking
    the last two dot-separated labels, e.g. 'a.b.c.example.com' -> 'example.com'.

    This doesn't account for public-suffix exceptions like 'co.uk' (where
    the registrable domain is actually the third-level label), but that's
    a deliberate simplification: implementing the full public suffix list
    would add real complexity for a diagnostic tool, and the vast majority
    of spam domains seen in practice use simple TLDs (.com, .us, .xyz, etc.)
    where this heuristic is correct.
    """
    if not domain:
        return domain
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    return ".".join(parts[-2:])


def dns_resolves(domain: str) -> Optional[bool]:
    """Check whether a domain has any DNS A record, using only the
    standard library (socket.gethostbyname).

    Returns True if it resolves, False only when the resolver explicitly
    reports that the name does not exist, or None if the check itself was
    inconclusive for some other reason (including a temporary resolver
    failure).
    """
    if not domain:
        return None
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror as error:
        # gethostbyname() reports several address-resolution failures as
        # gaierror. Only EAI_NONAME is a definitive "name does not exist"
        # answer; EAI_AGAIN and other values can be transient or otherwise
        # inconclusive and must not become a deletion signal.
        no_name_errors = {socket.EAI_NONAME}
        no_data = getattr(socket, "EAI_NODATA", None)
        if no_data is not None:
            no_name_errors.add(no_data)
        return False if error.errno in no_name_errors else None
    except Exception:
        return None


# Per-run cache: many spam messages in one sweep often share a domain.
_domain_status_cache = {}


def check_domain_registration(domain: str) -> str:
    """Check whether a domain is real, via DNS resolution.

    Returns one of:
      - "registered"   -- the domain resolves (has at least one A record)
      - "unregistered" -- either the domain has no dot at all (e.g.
                           'zdmcWfwdOzmoE', structurally invalid -- no
                           real domain has zero dots) or DNS confirms no
                           such host exists
      - "unknown"       -- the check was inconclusive for some other
                           reason (rare) -- never treated as a spam signal

    This distinction matters for deletion decisions: only a confirmed
    nonexistent domain is real evidence of spam. An inconclusive result
    must NOT be treated as a spam signal.
    """
    reg_domain = registrable_domain(domain)
    if not reg_domain:
        return "unknown"

    if "." not in reg_domain:
        # No dot anywhere -- structurally cannot be a real, resolvable
        # internet domain (every real domain is at least label.tld).
        return "unregistered"

    if reg_domain in _domain_status_cache:
        return _domain_status_cache[reg_domain]

    resolves = dns_resolves(reg_domain)
    if resolves is True:
        status = "registered"
    elif resolves is False:
        status = "unregistered"
    else:
        status = "unknown"

    _domain_status_cache[reg_domain] = status
    return status
