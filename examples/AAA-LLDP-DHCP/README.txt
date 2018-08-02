Example: AAA server calling the MUD Manager (MUD URI from LLDP, DHCP)

MUD Manger can be used by a AAA server to discover authorization policy for
constained devices. A NAS (e.g., Cisco Catalyst 9300) may deliver a MUD URI 
in a RADIUS accounting message as a Cisco-AVpair. This example shows how the 
FreeRADIUS AAA server can identify the MUD URI and provide it to the MUD i
Manger using the MUD Manger RESTful APIs. The MUD Manager will first return 
names of "dynamic ACLs" to the NAS, after which the NAS will request the dACL 
contents by name. 

Dependencies
============
FreeRADIUS 3.0.x. Although FreeRADIUS might be available in your distribution
from a package (e.g., using apt-get), this example requires the REST module, 
which is not included by default. Download and configuration instructions are 
below.

Perl 5. Earlier versions of Perl may also work but are untested.

Making FreeRADIUS
=================

1. Install dependancies for FreeRADIUS.

    sudo apt-get install -y libtalloc-dev
    sudo apt-get install -y libjson-c-dev
    sudo apt-get install -y libcurl4-gnutls-dev
    sudo apt-get install -y libperl-dev 
    sudo apt-get install -y libkqueue-dev
    sudo apt-get install -y libssl-dev

2. Download the source. Version 3.0.17 has been tested, but later versions are 
also likely to be fine.

    ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-3.0.17.tar.gz
    tar -xf freeradius-server-3.0.17.tar.gz
    cd freeradius-server-3.0.17

3. Make and install.

    ./configure --with-rest --with-json-c --with-perl
    make
    sudo make install

4. Apply configuration patches found in this directory as the "root" user. 

    sudo ./FR-setup.sh

    NOTE: If you have an older version of OpenSSL, you may get a message from
          radiusd that the OpenSSL version has a vulnerabilty and should be
	  updgraded. If you are working in a secure lab where you do not
	  expect an attacker to take advantage of that vunlernability, you
	  could instead add the following line within the "security" section of 
	  radiusd.conf:

	  allow_vulnerable_openssl = 'CVE-2016-6304'

5.  Add your NAS (e.g., Cisco Catalyst switch) as an authorized client to 
FreeRADIUS. Replace the IP address below with the IP address of your NAS, 
and use the "secret" configured on the NAS to talk to RADIUS servers.

    client 192.168.126.142 {
            ipaddr          = 192.168.126.142
	    secret          = cisco
    }

6. Start up the MUD Manager (e.g., using the luminaire example).

NOTE: If ths MUD Manager is not listening on its socket, FreeRADIUS won't 
      start properly.

7. Start the RADIUS server. It's helpful to start it in the foreground and
watch the messages

	sudo radiusd -Xxx

