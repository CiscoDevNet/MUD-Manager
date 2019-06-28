# Generating Device Certificates

To generate a test iDevID certificates for an IoT device, you can run the `run
.sh` file. This file will generate a root certificate, an intermediate  
certificate as well as a device iDevID certificate. 




# Deploying MUD in a wireless network

## wpa_supplicant configuration

You can use the following configuration to connect to the wireless network: 

```
ctrl_interface=/run/wpa_supplicant

network={
    ssid="yourwirelessssid"
    priority=1
    key_mgmt=WPA-EAP
    eap=TLS
    identity="user@example.org"
    client_cert="PATH/TO/CLIENT.pem"
    private_key="PATH/TO/CLIENT.key"
    private_key_passwd="PRIVATE KEY PASSWORD"
}
```

note that wpa_supplicant cannot be used while the network manager service is 
using. To make sure that the network-manager service is not using the 
wpa_supplicant, you should add the interface to the `/etc/network/interfaces`
. For instance if the interface is called `wlan0`, add the following to the 
end of the `/etc/network/interfaces` file:

```
allow-hotplug wlan0
iface wlan0 inet dhcp 
 wpa-conf /PATH/TO/WPA_SUPPLICANT.CONF
``` 

make sure the `iface wlan0` is not defined twice. Also, 
`/PATH/TO/WPA_SUPPLICANT.CONF` defines the path to the file in which you 
saved the above-mentioned configuration. After editing adding this 
information to the `/etc/network/interfaces`, you can take down the interface
 and bring it up again (as root) to intiate the connection: 
 
 ```
ifdown wlan0
ifup wlan0
```

**Note:** In case the wpa_spplicant did not connect successfully, there is a 
chance that the problem is caused by openssl version. Make sure that the TLS 
handshake is happening successfully: 

```
(2) eap: Expiring EAP session with state 0x214e522020e35f22
(2) eap: Finished EAP session with state 0x214e522020e35f22
(2) eap: Previous EAP request found for state 0x214e522020e35f22, released from the list
(2) eap: Peer sent packet with method EAP TLS (13)
(2) eap: Calling submodule eap_tls to process data
(2) eap_tls: Continuing EAP-TLS
(2) eap_tls: [eaptls verify] = ok
(2) eap_tls: Done initial handshake
(2) eap_tls: (other): before SSL initialization
(2) eap_tls: TLS_accept: before SSL initialization
(2) eap_tls: TLS_accept: before SSL initialization
(2) eap_tls: <<< recv TLS 1.3  [length 011c] 
(2) eap_tls: TLS_accept: SSLv3/TLS read client hello
(2) eap_tls: >>> send TLS 1.2  [length 003d] 
(2) eap_tls: TLS_accept: SSLv3/TLS write server hello
(2) eap_tls: >>> send TLS 1.2  [length 08e9] 
(2) eap_tls: TLS_accept: SSLv3/TLS write certificate
(2) eap_tls: >>> send TLS 1.2  [length 014d] 
(2) eap_tls: TLS_accept: SSLv3/TLS write key exchange
(2) eap_tls: >>> send TLS 1.2  [length 00d2] 
(2) eap_tls: TLS_accept: SSLv3/TLS write certificate request
(2) eap_tls: >>> send TLS 1.2  [length 0004] 
(2) eap_tls: TLS_accept: SSLv3/TLS write server done
(2) eap_tls: TLS_accept: Need to read more data: SSLv3/TLS write server done
(2) eap_tls: TLS - In Handshake Phase
(2) eap_tls: TLS - got 2914 bytes of data
(2) eap_tls: [eaptls process] = handled
(2) eap: Sending EAP Request (code 1) ID 174 length 1004
(2) eap: EAP session adding &reply:State = 0x214e522023e05f22
```  

an unsuccessful handshake might look partially like this: 

```
(2) eap_peap: TLS_accept: before SSL initialization
(2) eap_peap: TLS_accept: before SSL initialization
(2) eap_peap: <<< recv UNKNOWN TLS VERSION ?0304? [length 011c] 
(2) eap_peap: TLS_accept: SSLv3/TLS read client hello
(2) eap_peap: >>> send UNKNOWN TLS VERSION ?0304? [length 0058] 
(2) eap_peap: TLS_accept: SSLv3/TLS write server hello
(2) eap_peap: >>> send UNKNOWN TLS VERSION ?0304? [length 0001] 
(2) eap_peap: TLS_accept: SSLv3/TLS write change cipher spec
(2) eap_peap: TLS_accept: TLSv1.3 early data
(2) eap_peap: TLS_accept: Need to read more data: TLSv1.3 early data
```

where some of the TLS versions are indicated as `UNKNOWN`. Installing 
Libressl instead of Openssl might fix this issue. 
