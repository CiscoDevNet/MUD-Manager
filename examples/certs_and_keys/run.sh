#!/bin/bash

# making the bash files executable
find . -name "*.sh" | xargs chmod +x

# generating root certificate
./generate-root-ca.sh

# generating intermediate certificate
./generate-intermediate-ca.sh

# generating iDevID certificate
./generate-iDevID-8021AR.sh



