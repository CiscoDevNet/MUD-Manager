CERT=./MUD_FS_HTTPS_cert.pem
KEY=./MUD_FS_HTTPS_key.pem

python3 mud_https_server.py -c $CERT -k $KEY -p 443

