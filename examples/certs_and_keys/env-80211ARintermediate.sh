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

export cfgdir=`pwd`
export cadir=`pwd`/8021ARintermediate
export rootca=`pwd`/root
export format=pem
export interpass="env:interpass"
export pass="env:rootpass"

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
localityName="/L=ChangeMe Intermediate Locality"
organizationName="/O=ChangeMe Intermediate Org"
organizationalUnitName="/OU=Devices"
commonName="/CN=802.1AR CA"
DN=$countryName$stateOrProvinceName$localityName$organizationName
DN=$DN$organizationalUnitName$commonName
echo $DN
export subjectAltName=email:whatever@intermediate.example.com
echo $subjectAltName
