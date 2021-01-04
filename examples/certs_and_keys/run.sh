#!/bin/bash

# making the bash files executable
find . -name "*.sh" | xargs chmod +x

# generating root certificate
echo "generate-root-ca"
./generate-ca-root.sh
echo "generate-ca-8021AR"
# generating intermediate certificate
./generate-ca-8021AR.sh
echo "generate-freeradius-cert"
# generating FreeRADIUS certificate
./generate-freeradius-cert.sh
echo "generate-iDevID-8021AR"
# generating iDevID certificate
./generate-iDevID-8021AR.sh



