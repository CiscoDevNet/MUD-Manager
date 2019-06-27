# Example: AAA server calling the MUD Manager (MUD URI from LLDP, DHCP)

MUD Manger can be used by a AAA server to discover authorization policy for
constained devices. A NAS (e.g., Cisco Catalyst 9300) may deliver a MUD URI 
in a RADIUS accounting message as a Cisco-AVpair. This example shows how the 
FreeRADIUS AAA server can identify the MUD URI and provide it to the MUD i
Manger using the MUD Manger RESTful APIs. The MUD Manager will first return 
names of "dynamic ACLs" to the NAS, after which the NAS will request the dACL 
contents by name. 

## Dependencies

FreeRADIUS 3.0.x. Although FreeRADIUS might be available in your distribution
from a package (e.g., using apt-get), this example requires the REST module, 
which is not included by default. Download and configuration instructions are 
below.

Perl 5. Earlier versions of Perl may also work but are untested.

## Making FreeRADIUS

1. Install dependancies for FreeRADIUS.

    ```bash
    sudo apt-get install -y libtalloc-dev libjson-c-dev libcurl4-gnutls-dev \
    libperl-dev libkqueue-dev libssl-dev
    ```    

2. Download the source. Version 3.0.19 has been tested, but later versions are 
also likely to be fine.

    ```bash
    wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-3.0.19.tar.gz
    tar -xf freeradius-server-3.0.19.tar.gz
    cd freeradius-server-3.0.19
    ```

3. Make and install.

    ```bash
    ./configure --with-rest --with-json-c --with-perl
    make
    sudo make install
    ```

4. Apply configuration patches found in this directory as the "root" user. 

    ```bash
    sudo ./FR-setup.sh
    ```

    **NOTE**: If you have an older version of OpenSSL, you may get a message from
    radiusd that the OpenSSL version has a vulnerabilty and should be
    updgraded. If you are working in a secure lab where you do not
    expect an attacker to take advantage of that vunlernability, you
    could instead add the following line within the "security" section of 
    radiusd.conf:

    ``` bash
    allow_vulnerable_openssl = 'CVE-2016-6304'
    ```

5. Edit the file `clients.conf` in the FreeRADIUS folder and add your NAS (e
.g., Cisco Catalyst switch) as an authorized client to FreeRADIUS. Replace 
the IP address below with the IP address of your NAS, 
and use the "secret" configured on the NAS to talk to RADIUS servers.

    ```
    client 192.168.126.142 {
        ipaddr          = 192.168.126.142
        secret          = cisco
    }
    ```

6. Start up the MUD Manager (e.g., using the luminaire example).

    **NOTE**: If the MUD Manager is not listening on its socket, FreeRADIUS won't 
      start properly.

7. Start the RADIUS server. It's helpful to start it in the foreground and
watch the messages

    ```bash
    sudo radiusd -Xxx
    ```

8. If you have installed the luminair example,the following script will
verify that FreeRADIUS and the MUD Manager are communicating properly.

    ```bash
    ./kick_radius.sh
    ```
	
    You should see something like the following displayed:
    
    ```bash
    Sent Accounting-Request Id XX from 0.0.0.0:57752 to 127.0.0.1:1813 length 118
    Received Accounting-Response Id XX from 127.0.0.1:1813 to 127.0.0.1:57752 length 73
    ```
    
    The FreeRADIUS log should have lines something like the following:

    ```bash
    <date>  Debug: (0) Sent Accounting-Response Id XX from 127.0.0.1:1813 to 127.0.0.1:57752 length 0
    <date>  Debug: (0)   Cisco-AVPair = "ACS:CiscoSecure-Defined-ACL=mud-21966-v4fr.in"
    <date>  Debug: (0) Finished request
    ```
