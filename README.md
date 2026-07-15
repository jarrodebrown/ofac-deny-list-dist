# ofac-deny-list-dist

Public distribution point for an OFAC-based IP deny list, derived entirely from
public data (US Treasury OFAC CSVs + ipdeny.com country blocks). A daily GitHub
Actions workflow regenerates it and publishes an `ipset` add-list on the rolling
`deny-list` Release; a Ubiquiti EdgeRouter pulls and checksum-verifies it daily.
No private data lives here.
