"""Analysis modules, run in a fixed order so finding numbers are reproducible."""
from __future__ import annotations

from .activity import Activity
from .counterparties import Counterparties
from .idents import Identifiers
from .ips import IPs
from .links import Links
from .logins import Logins
from .quality import Quality
from .telecom import Telecom
from .temporal import Temporal
from .watchlist import Watchlist

MODULES = [Quality, IPs, Logins, Temporal, Links, Telecom, Identifiers, Counterparties, Watchlist, Activity]
