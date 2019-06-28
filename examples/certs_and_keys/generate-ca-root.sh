#!/bin/bash
##############################################################################
# The content of this file is taken from the "Guide for building an ECC pki"
# draft available at
# https://datatracker.ietf.org/doc/draft-moskowitz-ecdsa-pki/?include_text=1
##############################################################################


# setting the environment for root certificate by sourcing env-root.sh
. ./env-root.sh

# Create passworded keypair file

if [ ! -f $rootca/private/ca.key.$format ]; then
    echo GENERATING KEY
    openssl genpkey $pass -aes256 -algorithm ec\
            -pkeyopt ec_paramgen_curve:prime256v1\
            -outform $format -pkeyopt ec_param_enc:named_curve\
            -out $rootca/private/ca.key.$format
    chmod 400 $rootca/private/ca.key.$format
    openssl pkey $passin -inform $format -in $rootca/private/ca.key.$format\
            -text -noout
fi

# Create Self-signed Root Certificate file
# 7300 days = 20 years; Intermediate CA is 10 years.

echo GENERATING and SIGNING REQ
openssl req -x509 -config $cfgdir/openssl-root.cnf $passin \
     -set_serial 0x$(openssl rand -hex $sn)\
     -keyform $format -outform $format\
     -key $rootca/private/ca.key.$format -subj "$DN"\
     -new -days 7300 -sha256 -extensions v3_ca\
     -out $cadir/certs/ca.cert.$format

#

openssl x509 -inform $format -in $cadir/certs/ca.cert.$format -text -noout
openssl x509 -purpose -inform $format -in $cadir/certs/ca.cert.$format -inform $format
