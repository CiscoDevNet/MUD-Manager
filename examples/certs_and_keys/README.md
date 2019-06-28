# Deploying MUD in a wireless network

## Generating Certificate for the Device 

To generate a test iDevID certificates for an IoT device, you can run the `run
.sh` file. This file will generate a root certificate, an intermediate  
certificate as well as a device iDevID certificate. After generating the 
iDevIDs, you can check the certificates using the following command: 

```
openssl x509 -in examples/certs_and_keys/8021ARintermediate/certs/Wt1234.cert.pem -text -noout
```

The output should look similar to this:

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 5594583064329663739 (0x4da3f3a7d7c934fb)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, ST = IN, O = Cisco, OU = Devices, CN = 802.1AR CA
        Validity
            Not Before: Jun 28 02:47:08 2019 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: O = HTT Consulting, OU = Devices, serialNumber = Wt1234
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:2f:8f:86:b6:09:43:91:20:0e:82:9f:10:46:44:
                    d0:23:f3:9a:8a:77:ab:ec:96:3f:d3:5d:20:2c:f5:
                    e7:43:95:06:24:7f:a0:86:a4:6a:2b:f0:64:09:8d:
                    7a:46:a6:63:53:97:1b:b3:85:a0:af:c6:0f:35:db:
                    6c:86:da:e8:21
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Authority Key Identifier: 
                keyid:FF:85:01:B1:25:A1:C6:93:84:05:A4:AB:37:73:42:9B:A5:CD:F2:25
                DirName:/C=US/ST=IN/L=Indiana University/O=Cisco/OU=Devices/CN=Root CA
                serial:00

            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                othername:<unsupported>
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:85:08:f8:79:9d:59:bf:44:83:54:37:3d:76:
         6e:6e:35:37:23:14:88:ed:95:8c:6d:dc:e3:5f:b8:79:9d:17:
         8a:02:20:34:f1:96:16:8f:da:c8:37:34:cf:7a:77:80:33:d7:
         d2:95:5c:00:87:68:12:96:02:4a:2b:ae:cc:ab:8c:74:5e
``` 


## Generating Certificate for FreeRadius 

To deploy the MUD, you need to generate a certificate for the FreeRADIUS as 
well. The generated certificates should then be copied to `raddb/certs` 
folder. You can do this by running the following file:

```
cd MUD-Manager/example/certs-and-keys
./generate-freeradius-cert.sh 
```

This will generate the files named `server` in the `certs`, `csr` and 
`private` folders within `MUD-Manager-Vafa/examples/certs_and_keys/8021ARintermediate`. 
Next you have to copy the server file as well as the CA chain certificate to 
the FreeRADIUS folder. First make a backup of the `certs` folder in the 
`raddb` folder: 
```bash
sudo cp -r /usr/local/etc/raddb/certs /usr/local/etc/raddb/certs_bak
```
Then copy the certificates in the `raddb/certs`: 
```bash
cp MUD-Manager-Vafa/examples/certs_and_keys/8021ARintermediate/certs/ca-chain.cert.pem /usr/local/etc/raddb/certs/ca.pem
cp MUD-Manager-Vafa/examples/certs_and_keys/8021ARintermediate/certs/server.cert.pem /usr/local/etc/raddb/certs/server.pem
cp MUD-Manager-Vafa/examples/certs_and_keys/8021ARintermediate/private/server.key.pem /usr/local/etc/raddb/certs/server.key
```



**Important note:** After copying the `server` files to the `raddb/certs`, 
you should then modify the file `raddb/mods-available/eap`:

- Find `private_key_password=` and set the password
- Set the `private_key_file` file as follows: 
    ```
    private_key_file = ${certdir}/server.key
    ```
- Set the `certificate_file` file as follows:
    ```
    certificate_file = ${certdir}/server.pem
    ```

                

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
