Watchlists (optional)

Put CSV or TXT files here to have every case compared against them. A case can also have
its own lists in <case folder>\watchlists\. One entry per line:

    value,label,note
    159.89.0.0/16,Example hosting range,why it is on the list
    203.0.113.5,IP from a tip,lead 24-117
    bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq,BTC address from a tip,
    someone@example.com,,
    +17035550142,,

value  - an IP address, a CIDR range, an email, phone, crypto address, MAC, account name or other text
label  - optional; shown in the finding
note   - optional

Lines starting with # are ignored. Each hit is a priority-1 finding that cites the watchlist
file and line number; the list's SHA-256 is recorded in METHODS.md.
