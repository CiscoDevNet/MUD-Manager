#!/bin/bash
##############################################################################
# The content of this file is taken from the "Guide for building an ECC pki"
# draft available at
# https://datatracker.ietf.org/doc/draft-moskowitz-ecdsa-pki/?include_text=1
##############################################################################

#   Note: this files should be called from "generate-intermediate-ca.sh"
#   otherwise  that script would not run completely and properly
#
#
#
#   dir
#            Directory for certificate files
#
#   cadir
#
#            Directory for Root certificate files
#
#   Format
#            File encoding: PEM or DER
#            At this time only PEM works
#
#   sn
#            Serial Number length in bytes
#            For a public CA the range is 8 to 19

export cadir=`pwd`

export dir=$cadir/8021ARintermediate
mkdir $dir
cd $dir
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
sn=8 # hex 8 is minimum, 19 is maximum
echo 1000 > $dir/crlnumber

# cd $dir
export crlDP=
# For CRL support use uncomment these:
#crl=8021ARintermediate.crl.pem
#crlurl=www.htt-consult.com/pki/$crl
#export crlDP="URI:http://$crlurl"
export default_crl_days=30
export ocspIAI=
# For OCSP support use uncomment these:
#ocspurl=ocsp.htt-consult.com
#export ocspIAI="OCSP;URI:http://$ocspurl"

countryName="/C=US"
stateOrProvinceName="/ST=IN"
localityName="/L=Indiana University"
organizationName="/O=Cisco"
organizationalUnitName="/OU=Devices"
commonName="/CN=802.1AR CA"
DN=$countryName$stateOrProvinceName$localityName$organizationName
DN=$DN$organizationalUnitName$commonName
echo $DN
export subjectAltName=email:whatever@happens.com
echo $subjectAltName