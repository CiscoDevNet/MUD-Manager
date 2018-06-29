![alt text](https://github.com/CiscoDevNet/MUD-Manager/blob/master/MUDlogo.jpg)


# MUD-Manager

Manufacturer Usage Description (MUD) is a technique whereby constrained end devices (e.g., IoT devices) can signal to the network what sort of access and network functionality they require to properly function. The end device performs this signaling by issuing a URL in LLDP, DHCP, or as part of an X.509 certificate. A MUD Manager is a service sitting in the network that receives the MUD URL, fetches a MUD file containing access requirements provided by a manufacturer, and creates Access Control Lists (ACLs) that can be installed on network equipment to allow that access.

The MUD specification can be found in
(https://tools.ietf.org/html/draft-ietf-opsawg-mud-25), which has been approved to be an IETF RFC.

## How the MUD Manager is used
The MUD Manager is used by a RADIUS server to translate a MUD URL into access control policies. The MUD Manager receives REST APIs containing the MUD URL (and possibly other information), and returns RADIUS attributes that can be sent to a Network Access Device (NAD) such as an Ethernet switch. The NAD installs the policy on the access port, which restricts the device providing the MUD URL to just its required network access.

A MUD URL is an "https://..." file, which means that TLS is used to fetch the file.

## Install Requirements
The MUD manager depends on the following packages.

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

### Mongo C driver
The Mongo C driver is needed for the MUD manager to communicate with MongoDB. Download from https://github.com/mongodb/mongo-c-driver/releases. We suggest using version 1.7.0

    wget https://github.com/mongodb/mongo-c-driver/releases/download/1.7.0/mongo-c-driver-1.7.0.tar.gz

Untar, cd into the mongo-c-driver-1.7.0 directory, and build it.

    ./configure --disable-automatic-init-and-cleanup --with-libbson=bundled
    make
    sudo make install
 
### Mongoose
You will need the mongoose package, which provides JSON utilities.
 
        git clone https://github.com/cesanta/mongoose

You do NOT need to directly make anything in this package - it will be referenced from the MUD manager during the make process.

## Building the MUD Manager

Run configure and make. The location of the mongoose pakage needs to be provided. In this example, we assume mongoose was unzipped on the system one directory level up from the MUD controller source. 
 
        ./configure --with-mongoose=../mongoose
        make
        sudo make install

## Editing the configuration file.
The default location for the configuration file is:

        /usr/local/etc/mud_manager_config.json

The following fields can be set in the configuration file

### MUDManagerAPIProtocol

This defines whether the REST APIs should be 'http://. or 'https://'. The default configuration file setting is 'http://'.

If 'https://' is used, then the MUD Manager will also need the following TLS-related fields added:

* MUDManager_cert, with a pathname to the MUD Manager's signing certificate
* MUDManager_key, with a pathname to the MUD Manger's private key
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



