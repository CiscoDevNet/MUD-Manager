#!/bin/bash

# making the bash files executable
find . -name "*.sh" | xargs chmod +x

# generating root certificate

echo -n "Enter passphrase for root certificate: "
stty -echo
read rootpass
echo
echo -n "Confirm: "
read rootpass2
stty echo
echo

if [ x$rootpass != x$rootpass2 ]; then
    echo "Passwords do not match."
    exit 1
fi
export rootpass

echo -n "Enter passphrase for intermediate certificate: "
stty -echo
read interpass
echo
echo -n "Confirm: "
read interpass2
echo
stty echo
if [ x$interpass != x$interpass2 ]; then
    echo "Passwords do not match."
    exit 1
fi

export interpass

./generate-ca-root.sh


# generating intermediate certificate
./generate-ca-8021AR.sh

echo "generate-freeradius-cert"
# generating FreeRADIUS certificate
./generate-freeradius-cert.sh

echo "generate-iDevID-8021AR"
# generating iDevID certificate
./generate-iDevID-8021AR.sh



