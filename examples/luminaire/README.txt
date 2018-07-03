Example: luminaire

The files in this directory provide a quick example to show how the MUD Manager works. They assume that
the package has been made and installed.

You may need three shells: one to start the MUD file server, one start the MUD manager, and one to run a
test command.

(1) Start a MUD file server. Change to the "fs" directory and start the script. This can be done on the
same host as the MUD Manager, or can be on a different server. Note: This is just a test scenario --
the MUD file would typically be located on a MUD file server provided by the manufacturer of the
device, not the organization using the MUD Manager.

	sudo ./start_https_mudserver.sh

Note: This starts the MUD server on port 443.

(2) Update /etc/hosts to indicate that "luminaire.example.com" resolves to an address on the host
running the MUD file server.

	sudo vi /etc/hosts

If the MUD file server is running on the same host as the MUD Manager, add the following line.

    	127.0.0.1       luminaire.example.com

(3) Place the luminaire-cacert.pem file in the location specified by the  configuration file

	sudo mkdir /home/mudtester
	sudo cp luminaire-cacert.pem /home/mudtester

(4) Ensure that the MongoDB collections used by the MUD Manager are empty

	mud_clobber_db

(5) Start the MUD Manager using the configuration file in this example.

	mud_manager -f ./luminaire_conf.json

(6) Run the following command

	./test_client -f Luminaire_150 -c 127.0.0.1:8000 -w luminaire.example.com

The output should look similar to the test_client_output.txt in this directory.
