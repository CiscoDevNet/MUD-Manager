# Example: luminaire

The files in this directory provide a quick example to show how the MUD
Manager works. They assume that the package has been made and installed.

You may need three shells: one to start the MUD file server, one start the
MUD manager, and one to run a test command.

1. Start a MUD file server. Change to the `fs` directory and start the
script. This can be done on the same host as the MUD Manager, or can be on a
different server. 

    **Note**: This is just a test scenario -- the MUD file would
    typically be located on a MUD file server provided by the manufacturer of
    the device, not the organization using the MUD Manager.
    
    ```bash
    sudo ./start_https_mudserver.sh
    ```

    **Note**: This starts the MUD server on port 443.

2. Update /etc/hosts to indicate that "luminaire.example.com" resolves to
an address on the host running the MUD file server.

    ```bash
    sudo vi /etc/hosts
    ```

    If the MUD file server is running on the same host as the MUD Manager,
    add the following line.
    
    ```
    127.0.0.1	luminaire.example.com
    ```

3. Place the `luminaire-cacert.pem` file in the location specified by the 
configuration file

    ```bash
    sudo mkdir /home/mudtester 
    sudo cp luminaire-cacert.pem /home/mudtester
    ```

4. Ensure that the MongoDB collections used by the MUD Manager are empty

    ```bash
    mud_clobber_db
    ```

5. Start the MUD Manager using the configuration file in this example.

    ```bash
    mud_manager -f ./luminaire_conf.json
    ```

6. Run the following command

```bash
mud_test_client -f Luminaire_150 -c 127.0.0.1 -p 8000 -w luminaire.example.com
```

The output should look similar to the `test_client_output.txt` in this 
directory:

```
URL:  https://luminaire.example.com/Luminaire_150

Starting RESTful client against http://127.0.0.1:8000/getaclname
    with request {
        "MUD_URI":      "https://luminaire.example.com/Luminaire_150"
}
Got ACL Names
Full ACL Name 0: ACS:CiscoSecure-Defined-ACL=mud-21966-v4fr.in
ACLname: mud-21966-v4fr.in

Starting RESTful client against http://127.0.0.1:8000/getaclpolicy with
request {
        "ACL_NAME":     "mud-21966-v4fr.in"
}
Username: mud-21966-v4fr.in
Got DACL contents:
        ACE: ip:inacl#10=permit tcp any host 172.12.212.10 range 443 443
established
        ACE: ip:inacl#20=permit udp any host 10.1.1.4 range 5684 5684
        ACE: ip:inacl#30=permit udp any host 255.255.255.255 range 5683 5683
        ACE: ip:inacl#40=permit udp any any eq 53
        ACE: ip:inacl#41=deny ip any any
```

