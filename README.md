![alt text](https://github.com/CiscoDevNet/MUD-Manager/blob/master/MUDlogo.jpg)


# MUD-Manager

Manufacturer Usage Description (MUD) is a technique whereby constrained end devices (e.g., IoT devices) can signal to the network what sort of access and network functionality they require to properly function. The end device performs this signaling by issuing a URL in LLDP, DHCP, or as part of an X.509 certificate. A MUD Manager is a service sitting in the network that receives the MUD URL, fetches a MUD file containing access requirements provided by a manufacturer, and creates Access Control Lists (ACLs) that can be installed on network equipment to allow that access.

The MUD specification can be found in
(https://tools.ietf.org/html/draft-ietf-opsawg-mud-25), which has been approved to be an IETF RFC.

After you have installed the MUD Manager, guidance is available at (https://developer.cisco.com/docs/mud/#!mud-developer-guide) if you need help creating a MUD file, and/or preparing a device to emit a URL to a MUD file.

## How the MUD Manager is used
The MUD Manager is used by a RADIUS server to translate a MUD URL into access control policies. The MUD Manager receives REST APIs containing the MUD URL (and possibly other information), and returns RADIUS attributes that can be sent to a Network Access Device (NAD) such as an Ethernet switch. The NAD installs the policy on the access port, which restricts the device providing the MUD URL to just its required network access.

A MUD URL is an "https://..." file, which means that TLS is used to fetch the file.

## Dependancies
The MUD manager depends on the following packages.

### OpenSSL
OpenSSL is used for cryptographic services, and is available on most Linux systems. If not, then a recent release will need to be installed. It may be available using a package installer (such as apt-get), else it can be downladed from https://www.openssl.org. 

### cJSON
cJSON is used for JSON processing in "C". Download it from (https://github.com/DaveGamble/cJSON)

        git clone https://github.com/DaveGamble/cJSON
        cd cJSON 
        make
        sudo make install

### MongoDB
MongoDB is used to store the MUD URLs, policy derived from the MUD URLs, and MAC addresses that are associated with a MUD URL.

Most likely MongoDB can be installed using a package tool such as apt-get:

        sudo apt-get install -y mongodb


Alternatively it can be downloaded with git, and the follow the instructions in its README.

        git clone https://github.com/mongodb/mongo.git

The MongoDB service should be started automatically when the system boots. If you see an indication that the MUD Manager cannot reach the MongoDB server, you can try

        sudo service mongodb start

### Mongo C driver
The Mongo C driver is needed for the MUD manager to communicate with MongoDB. Download from https://github.com/mongodb/mongo-c-driver/releases. We suggest using version 1.7.0

    wget https://github.com/mongodb/mongo-c-driver/releases/download/1.7.0/mongo-c-driver-1.7.0.tar.gz

Untar, cd into the mongo-c-driver-1.7.0 directory, and build it.

    ./configure --disable-automatic-init-and-cleanup --with-libbson=bundled
    make
    sudo make install

### libcurl
Libcurl is used to fetch MUD files from a MUD file server.

    sudo apt-get install libcurl4-openssl-dev
 

## Building the MUD Manager

Run configure and make. 
 
        ./configure 
        make
        sudo make install

## Editing the configuration file.
The default location for the configuration file is:

        /usr/local/etc/mud_manager_config.json

The following fields can be set in the configuration file.

### MUDManagerAPIProtocol

This defines whether the REST APIs should be 'http://. or 'https://'. The default configuration file setting is 'http://'.

If 'https://' is used, then the MUD Manager will also need the following TLS-related fields added:

* MUDManager_cert, with a pathname to the MUD Manager's signing certificate
* MUDManager_key, with a pathname to the MUD Manager's private key
* Enterprise_CACert, with a pathname to the CA certificate that signed the MUDManager_cert

### ACL_Type

This directs the MUD manager to return ACLs only to enforce policy on the "ingress" direction (i.e., from the device), or whether to enforce policy on both ingress and egress (i.e., to and from the device). Its setting depends on the capabilities of the NAD. 

The safest choice is to leave it as "dACL-ingress-only", however if you have a NAD that will also enforce egress policy you should set it as "dACL-ingress-egress".

### COA_Password
In some cases, a RADIUS server will complete an  Authentication exchange for a device before the NAD gives it a MUD URL associated with that device. When the association is subsequently made, the MUD policy will not become effective on the NAD before the next Authentication session. A convenient way to cause the Authentication to happen is for the MUD manager to send a Change of Authorization (CoA) to the NAD, instructing it to perform authentication with the RADIUS server again.

For the CoA to succeed, the MUD Manager must share a password with the NAD. Replace the sample password provided in the configuration file with the password you use on the NAD.

### Manufacturers
Each MUD file is accompanied by a signature file that verifies that the MUD file was indeed generated by the manufacturer. The MUD manager needs some basic information about each manufacturer.

#### authority

The authority name of the URL, which defines the unique manufacturer.

#### cert

The CA certificate for the manufacturer, which is used to verify the MUD file server signature.

#### https_port

The port used to contact the file server (e.g., 443).

#### my_controller_v4, my_controller_v6

These are used to define what is the local IP address for a "my-contoller" statement found in a MUD file.

#### local_networks_v4, local_networks_v6

These are used to translate a "local-networks" statement found in a MUD file.

#### vlan

If a "same-manufacturer" statement is found in the MUD file, this VLAN value is sent with the ACLs to the NAD. Thesame VLAN value should be conigured for each type of device from that manufacturer that needs to communicate.

#### DNSMapping, DNSMapping_v6

If a MUD file has a DNS name in it, and the name needs to be translated to an IP address, the translation can be set here.

#### ControllerMapping, ControllerMapping_v6

If a MUD file has a "controller" statement,it needs to be translated to an IP address. Do that here.

#### DefaultACL, DefaultACL_v6

A site policy may provide additional restrictions to the devices. These can be defined as access control list statements here. The default policy included in the configuration policy is to block all othe IP and ICMP packets.

## MongoDB Tools

Two scripts are included to manipulate the MUD Manager collections in MongoDB.
  * mud_clobber_db. This can be used to clean out the MUD Manager collections, which forces MUD files to be fetched and access policy to be re-gererated.
  * mud_show_db. This displays the contents of the three collections used by the MUD Manager.

## Examples

The examples directory includes an example of a "luminaire", which includes a sample MUD file, sample MUD file server, certificates, and instructions how to use the mud_test_command to invoke the MUD Manager. 

## MUD Manager Test Command

A simple test command is included, which initates REST APIs to the MUD Manager and verifies that the MUD Manager can download and process a  MUD file.

If the "luminaire" example MUD file server is running, and the MUD manage is started on its default port, then the following test command should retrieve the MUD file and the return the ACLs contained within it.

    mud_test_client -f Luminaire_150 -c 127.0.0.1 -p 8000 -w luminaire.example.com

The output should look something like this:

        URL:  https://luminaire.example.com/Luminaire_150
        
        Starting RESTful client against http://127.0.0.1:8000/getaclname
            with request {
                "MUD_URI":      "https://luminaire.example.com/Luminaire_150"
        }
        Got ACL Names
        Full ACL Name 0: ACS:CiscoSecure-Defined-ACL=mud-21966-v4fr.in
        ACLname: mud-21966-v4fr.in
        
        Starting RESTful client against http://127.0.0.1:8000/getaclpolicy with request {
                "ACL_NAME":     "mud-21966-v4fr.in"
        }
        Username: mud-21966-v4fr.in
        Got DACL contents:
                ACE: ip:inacl#10=permit tcp any host 172.12.212.10 range 443 443 established
                ACE: ip:inacl#20=permit udp any host 10.1.1.4 range 5684 5684
                ACE: ip:inacl#30=permit udp any host 255.255.255.255 range 5683 5683
                ACE: ip:inacl#40=permit tcp any eq 22 any
                ACE: ip:inacl#41=deny ip any any

## Contributers
Rashmikant Shah

[Brian Weis](https://github.com/iggy2028)

[Cheryl Madson](https://github.com/cmadsoncisco)

