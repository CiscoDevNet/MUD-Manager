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

echo -n "Generating root CA cert... "
./generate-ca-root.sh > run.log 2>&1

if [ $? = 1 ]; then
    echo
    echo "error in generate-ca-root.sh: check run.log"
    exit 1
fi

echo "[ok]"
echo -n "Generating intermediate certificate... "

# generating intermediate certificate
./generate-ca-8021AR.sh >> run.log 2>&1

if [ $? = 1 ]; then
    echo
    echo "error in generate-ca-8021AR.sh: check run.log"
    exit 1
fi

echo "[ok]"
echo -n "Generating freeradius certificate... "

# generating FreeRADIUS certificate
./generate-freeradius-cert.sh >> run.log 2>&1

if [ $? = 1 ]; then
    echo
    echo "error in generate-freeradius-cert.sh: check run.log"
    exit 1
fi

echo "[ok]"
echo -n "Generating iDevID... "

# generating iDevID certificate
./generate-iDevID-8021AR.sh >> run.log 2>&1

if [ $? = 1 ]; then
    echo
    echo "error in generate-iDevID-8021AR.sh: check run.log"
    exit 1
fi

echo "[ok]"
echo "All keys and certificates are generated.  Check run.log for details."

