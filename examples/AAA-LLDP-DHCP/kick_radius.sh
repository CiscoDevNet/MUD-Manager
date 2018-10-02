#!/bin/sh

#
# This test command will send a RADIUS accounting message containing a MUD URI
# to a FreeRADIUS server. If the FreeRADIUS server is confgured with the MUD
# Manager, and the MUD manager has a known MUD file server, then it should be
# fetched and a single Cisco DACL returned.
#
# A successful return will have a message similar to the following in the
# FreeRADIUS log:
#
# <date>  Debug: (0) Sent Accounting-Response Id XX from 127.0.0.1:1813 to 127.0.0.1:39143 length 0
# <date>  Debug: (0)   Cisco-AVPair = "ACS:CiscoSecure-Defined-ACL=mud-21966-v4fr.in"
# <date>  Debug: (0) Finished request
#

radclient localhost:1813 acct cisco <<EOF
User-Name=b827ebc91c0a
Acct-Status-Type=Interim-Update
Acct-Session-Id=0000003b
Cisco-AVpair="lldp-tlv=\000\177\000/\000\000^\001https://luminaire.example.com/Luminaire_150"
EOF
