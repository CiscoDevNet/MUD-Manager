#!/bin/bash
##############################################################################
# The content of this file is taken from the "Guide for building an ECC pki"
# draft available at
# https://datatracker.ietf.org/doc/draft-moskowitz-ecdsa-pki/?include_text=1
##############################################################################



# setting the environment for root certificate by sourcing env-intermediate.sh
. ./env-80211ARintermediate.sh

mkdir $cadir
(
    #do some work in $cadir
cd $cadir
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
sn=8 # hex 8 is minimum, 19 is maximum
)
echo 1000 > $cadir/crlnumber


# Create passworded keypair file

openssl genpkey -aes256 -algorithm ec\
   -pkeyopt ec_paramgen_curve:prime256v1 \
   -outform $format -pkeyopt ec_param_enc:named_curve\
   -out $cadir/private/8021ARintermediate.key.$format
chmod 400 $cadir/private/8021ARintermediate.key.$format
openssl pkey -inform $format\
   -in $cadir/private/8021ARintermediate.key.$format -text -noout

# Create the CSR

openssl req -config $cfgdir/openssl-root.cnf\
   -key $cadir/private/8021ARintermediate.key.$format \
   -keyform $format -outform $format -subj "$DN" -new -sha256\
   -out $cadir/csr/8021ARintermediate.csr.$format
openssl req -text -noout -verify -inform $format\
   -in $cadir/csr/8021ARintermediate.csr.$format

# Create 802.1AR Intermediate Certificate file
# The following does NOT work for DER

openssl rand -hex $sn > $cadir/serial # hex 8 is minimum, 19 is maximum
# Note 'openssl ca' does not support DER format

export intdir=$cadir

cadir=$rootca openssl ca -config $cfgdir/openssl-root.cnf -days 3650\
   -extensions v3_intermediate_ca -notext -md sha256\
   -in $intdir/csr/8021ARintermediate.csr.$format\
   -out $intdir/certs/8021ARintermediate.cert.pem
chmod 444 $cadir/certs/8021ARintermediate.cert.$format

openssl verify -CAfile $cfgdir/certs/ca.cert.$format\
    $dir/certs/8021ARintermediate.cert.$format

openssl x509 -noout -text\
    -in $cadir/certs/8021ARintermediate.cert.$format

# Create the certificate chain file

cat $cadir/certs/8021ARintermediate.cert.$format\
  $cfgdir/certs/ca.cert.$format > $cfgdir/certs/ca-chain.cert.$format
chmod 444 $cfgdir/certs/ca-chain.cert.$format
