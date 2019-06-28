#!/bin/bash

# making the bash files executable
find . -name "*.sh" | xargs chmod +x

# generating root certificate
./generate-ca-root.sh

# generating intermediate certificate
./generate-ca-8021AR.sh

# generating iDevID certificate
./generate-iDevID-8021AR.sh



