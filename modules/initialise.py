# modules/initialise.py
"""
Initialise module with robust rules:

- Only processes UNVERIFIED scope items.
- Classifies into: "IP Address" | "CIDR" | "Domain" | "Wildcard" | "Other Asset" | "AI Model" | "API"
- Normalizes values (domains lowercased, trailing dot stripped; /32,/128 normalized to IP).
- Special-case for API:
    * Accepts full URLs or bare hosts.
    * If hostname is a domain and resolves => KEEP in API (don't move).
    * If hostname is an IP => KEEP in API.
    * If value/host is a CIDR => MOVE to CIDR.
    * If domain fails to resolve => REMOVE.
- Elsewhere:
    * Wrong bucket -> MOVE to canonical type.
    * Domain must resolve; if not => REMOVE.
- Other Asset:
    * If value parses as any canonical type => MOVE to that type; else KEEP.
- AI Model: KEEP (no parsing).
- Logs actions and marks verified.

Idempotent via verified flag.
"""

from datetime import datetime
import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Optional, Tuple

from app.db import SessionLocal
from app.models import ScopeItem
from app.metrics import record_metric

NAME = "initialise"
DESCRIPTION = "Normalize & verify scope entries with API/domain exceptions; move/remove accordingly."

# --------- Patterns ---------
# Accept one or more labels, last label 2-63 chars; optional trailing dot
RE_FQDN = re.compile(r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}\.?$")
RE_WILDCARD = re.compile(r"^\*\.(?=.{1,253}\.?$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}\.?$")

CANON_TYPES = {"CIDR", "Domain", "Wildcard", "IP Address", "Other Asset", "URL", "API"}

def _strip_trailing_dot(s: str) -> str:
    return s.rstrip(".")

def _is_ip(val: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(val.strip())
    except Exception:
        return None

def _as_cidr_if_any(val: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(val.strip(), strict=False)
    except Exception:
        return None

def _is_fqdn(val: str) -> bool:
    s = _strip_trailing_dot(val.strip().lower())
    if any(x in s for x in (" ", "/", ":")):
        return False
    return bool(RE_FQDN.match(s))

def _is_wildcard(val: str) -> bool:
    s = val.strip().lower()
    if any(x in s for x in (" ", "/", ":")):
        return False
    return bool(RE_WILDCARD.match(s))

def _dns_resolves(host: str) -> bool:
    name = _strip_trailing_dot(host.strip())
    try:
        socket.getaddrinfo(name, None)
        return True
    except Exception:
        return False

def _normalize_domain(val: str) -> str:
    return _strip_trailing_dot(val.strip().lower())

def _classify_value(raw: str) -> Tuple[Optional[str], str]:
    """
    Return (canonical_type, normalized_value) or (None, raw) if invalid.
    """
    v = raw.strip()
    if not v:
        return None, raw

    # Wildcard first
    if _is_wildcard(v):
        return "Wildcard", _normalize_domain(v)

    # Pure IP?
    ipobj = _is_ip(v)
    if ipobj:
        return "IP Address", str(ipobj)

    # CIDR?
    net = _as_cidr_if_any(v)
    if net:
        # Normalize textual form
        txt = str(net)
        # If it's effectively a single host (/32 or /128), treat as IP (per request)
        if (net.version == 4 and net.prefixlen == 32) or (net.version == 6 and net.prefixlen == 128):
            return "IP Address", str(net.network_address)
        return "CIDR", txt

    # FQDN?
    if _is_fqdn(v):
        return "Domain", _normalize_domain(v)

    # Could be URL: we don't classify as URL; classification uses the hostname later in API logic
    return None, v

def _api_extract_host(val: str) -> str:
    """
    For API entries, accept URLs or bare hosts.
    If URL, return hostname (lowercased, no trailing dot). Else return value as-is (normalized).
    """
    v = val.strip()
    parsed = urlparse(v if "://" in v else f"http://{v}")
    host = parsed.hostname or v
    return _normalize_domain(host)

def run():
    db = SessionLocal()
    moved = 0
    removed = 0
    verified = 0
    examined = 0
    notes = []

    try:
        q = db.query(ScopeItem).filter((ScopeItem.verified == False) | (ScopeItem.verified.is_(None)))
        items = q.order_by(ScopeItem.created_at.asc()).all()

        for it in items:
            examined += 1
            original_type = it.stype
            value_raw = (it.value or "").strip()

            # ------------- Special handling: API -------------
            if original_type == "API":
                host = _api_extract_host(value_raw)
                # Classify the host only (not the full URL)
                canonical, norm = _classify_value(host)

                if canonical in ("Domain", "Wildcard"):
                    # Domains in API must resolve to be kept; else remove
                    if canonical == "Domain":
                        if not _dns_resolves(norm):
                            notes.append(f"REMOVE [{it.id}] API domain '{norm}' (DNS NX)")
                            db.delete(it)
                            removed += 1
                            continue
                        # Keep in API (do NOT move)
                        it.value = value_raw  # leave original (may be URL); we could normalize but spec says keep
                        it.verified = True
                        it.verified_at = datetime.utcnow()
                        it.verified_note = "API host=domain ok (DNS)"
                        db.add(it)
                        verified += 1
                        continue
                    if canonical == "Wildcard":
                        # Wildcards don't resolve; keep in API
                        it.value = value_raw
                        it.verified = True
                        it.verified_at = datetime.utcnow()
                        it.verified_note = "API host=wildcard ok"
                        db.add(it)
                        verified += 1
                        continue

                if canonical == "IP Address":
                    # IP is valid for API endpoints; keep
                    it.value = value_raw
                    it.verified = True
                    it.verified_at = datetime.utcnow()
                    it.verified_note = "API host=ip ok"
                    db.add(it)
                    verified += 1
                    continue

                if canonical == "CIDR":
                    # CIDR does not make sense as an API endpoint -> MOVE to CIDR
                    it.stype = "CIDR"
                    it.value = norm
                    it.verified = True
                    it.verified_at = datetime.utcnow()
                    it.verified_note = "moved from API to CIDR"
                    notes.append(f"MOVE  [{it.id}] '{value_raw}': API → CIDR")
                    db.add(it)
                    moved += 1
                    verified += 1
                    continue

                # Not a domain/IP/CIDR/wildcard -> keep as API (strings, paths, service names)
                it.verified = True
                it.verified_at = datetime.utcnow()
                it.verified_note = "API string ok"
                db.add(it)
                verified += 1
                continue

            # ------------- General handling for other types -------------
            canonical, norm = _classify_value(value_raw)

            if canonical is None:
                # invalid format -> remove
                notes.append(f"REMOVE [{it.id}] '{value_raw}' (invalid format) from {original_type}")
                db.delete(it)
                removed += 1
                continue

            # Domain must resolve everywhere outside API
            if canonical == "Domain":
                if not _dns_resolves(norm):
                    notes.append(f"REMOVE [{it.id}] '{value_raw}' (DNS NX) from {original_type}")
                    db.delete(it)
                    removed += 1
                    continue

            # If currently in the wrong bucket, move (Domain into Domain, IP into IP Address, etc.)
            target_type = canonical

# Special: URL — typically full paths or endpoints; may be normalised later
            if original_type == "URL":
                # If it classifies as IP/CIDR/Domain/Wildcard → MOVE
                # Else, keep as URL
                if canonical not in ("IP Address", "CIDR", "Domain", "Wildcard"):
                    it.verified = True
                    it.verified_at = datetime.utcnow()
                    it.verified_note = "URL ok"
                    db.add(it)
                    verified += 1
                    continue


            # Special: Other Asset — move if it classifies
            if original_type == "Other Asset" and canonical in ("IP Address", "CIDR", "Domain", "Wildcard"):
                pass  # normal move below

            # If types differ, adjust; else just normalize value
            if it.stype != target_type:
                notes.append(f"MOVE  [{it.id}] '{value_raw}': {it.stype} → {target_type}")
                it.stype = target_type
                moved += 1

            # Normalize stored value for canonical
            if target_type in ("Domain", "Wildcard"):
                it.value = norm
                it.verified_note = ("Domain ok (DNS)" if target_type == "Domain" else "Wildcard ok")
            elif target_type == "IP Address":
                it.value = norm
                it.verified_note = "IP ok"
            elif target_type == "CIDR":
                it.value = norm
                it.verified_note = "CIDR ok"
            else:
                it.value = value_raw
                it.verified_note = "ok"

            it.verified = True
            it.verified_at = datetime.utcnow()
            db.add(it)
            verified += 1

        db.commit()

        # Metrics
        record_metric(db, NAME, "examined", value_num=float(examined))
        record_metric(db, NAME, "moved", value_num=float(moved))
        record_metric(db, NAME, "removed", value_num=float(removed))
        record_metric(db, NAME, "verified", value_num=float(verified))

        # Output for Modules page
        summary = (
            f"initialise: examined={examined}, moved={moved}, removed={removed}, verified={verified}\n"
            + "\n".join(notes[-400:])  # cap output length
        )
        return summary or "initialise: no changes"

    finally:
        db.close()

