"""Date parsing/formatting. Storage is always UTC ISO (`YYYY-MM-DDTHH:MM:SS+00:00`, lexicographically
sortable); input and display use the local timezone."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
FMT = "%Y-%m-%dT%H:%M:%S+00:00"
_REL = re.compile(r"^(\d+(?:\.\d+)?)\s*([hdwmy])$", re.I)
_UNIT = {"h": 1 / 24, "d": 1, "w": 7, "m": 30, "y": 365}


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime(FMT)


def now_iso() -> str:
    return iso(utcnow())


def local_tz():
    return datetime.now().astimezone().tzinfo


def parse_date(s: str, *, end_of_day: bool = False, sane: bool = False) -> datetime | None:
    """Lenient parser. Accepts YYYY-MM-DD, DD/MM/YYYY (05/10/2026 = 5 Oct), DD.MM.YYYY and ISO datetimes.
    Date-only values are local midnight (or end of day). Year-only / unparseable -> None.
    sane=True additionally rejects dates >2 days in the future (bogus page metadata)."""
    if not s:
        return None
    s = str(s).strip()
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?)?", s)
    dt = None
    try:
        if m:
            y, mo, d, hh, mi, ss, tz = m.groups()
            if hh is None:
                dt = datetime(int(y), int(mo), int(d), tzinfo=local_tz())
                if end_of_day:
                    dt += timedelta(days=1) - timedelta(seconds=1)
            else:
                if tz in (None, "Z"):
                    zone = UTC
                else:
                    sign = 1 if tz[0] == "+" else -1
                    t = tz[1:].replace(":", "")
                    zone = timezone(sign * timedelta(hours=int(t[:2]), minutes=int(t[2:])))
                dt = datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss or 0), tzinfo=zone)
        else:
            m = re.fullmatch(r"(\d{1,2})[/.](\d{1,2})[/.](\d{4})", s)
            if m:
                d, mo, y = map(int, m.groups())
                dt = datetime(y, mo, d, tzinfo=local_tz())
                if end_of_day:
                    dt += timedelta(days=1) - timedelta(seconds=1)
    except ValueError:
        return None
    if dt and sane and dt > utcnow() + timedelta(days=2):
        return None
    return dt


def parse_since(spec: str, now: datetime | None = None) -> datetime:
    """'24h' / '7d' / '30d' / '1y' / '2w' / a date -> lower bound (UTC)."""
    now = now or utcnow()
    spec = spec.strip()
    m = _REL.match(spec)
    if m:
        return now - timedelta(days=float(m.group(1)) * _UNIT[m.group(2).lower()])
    d = parse_date(spec)
    if not d:
        raise ValueError(f"cannot understand '{spec}' — use 24h, 7d, 30d, 1y, YYYY-MM-DD or DD/MM/YYYY")
    return d.astimezone(UTC)


def parse_range(frm: str | None, to: str | None) -> tuple[datetime | None, datetime | None]:
    a = b = None
    if frm:
        a = parse_date(frm)
        if not a:
            raise ValueError(f"bad --from date '{frm}' (use YYYY-MM-DD or DD/MM/YYYY)")
        a = a.astimezone(UTC)
    if to:
        b = parse_date(to, end_of_day=True)
        if not b:
            raise ValueError(f"bad --to date '{to}' (use YYYY-MM-DD or DD/MM/YYYY)")
        b = b.astimezone(UTC)
    if a and b and a > b:
        raise ValueError(f"--from ({frm}) is after --to ({to})")
    return a, b


def parse_window(spec) -> float | None:
    """Recency window -> days (None = any). Accepts 7, '7', '24h', '7d', '30d', '1y', 'any'."""
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("any", "all", "none", "off", "0", ""):
        return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        v = float(s)
    else:
        m = _REL.match(s)
        if not m:
            raise ValueError("recency must be a number of days, 24h, 7d, 30d, 1y or 'any'")
        v = float(m.group(1)) * _UNIT[m.group(2).lower()]
    if v <= 0:
        return None
    return v


def window_text(days: float | None) -> str:
    if days is None:
        return "any"
    return f"{int(days * 24)}h" if days < 1 else (f"{days:g}d")


def cutoff_iso(days: float | None, now: datetime | None = None) -> str | None:
    return None if days is None else iso((now or utcnow()) - timedelta(days=days))


def to_local(iso_s: str | None) -> str:
    """Display form in the local timezone; '-' when unknown."""
    if not iso_s:
        return "-"
    d = parse_date(iso_s)
    return d.astimezone(local_tz()).strftime("%Y-%m-%d %H:%M") if d else "-"


def to_local_day(iso_s: str | None) -> str:
    return to_local(iso_s)[:10] if iso_s else "-"


def in_window(effective: str | None, days: float | None, now: datetime | None = None) -> bool:
    """Is an effective date inside the window? None effective -> False (unknown never counts as new)."""
    if not effective:
        return False
    if days is None:
        return True
    return effective >= cutoff_iso(days, now)  # type: ignore[operator]
