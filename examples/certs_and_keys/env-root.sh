#!/bin/bash
##############################################################################
# The content of this file is taken from the "Guide for building an ECC pki"
# draft available at
# https://datatracker.ietf.org/doc/draft-moskowitz-ecdsa-pki/?include_text=1
##############################################################################

#   Note: this files should be called from "generate-root-ca.sh" otherwise that
#   script would not run completely and properly
#
#
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

export cadir=`pwd`/root
export cfgdir=`pwd`
export format=pem
export default_crl_days=65
export pass="env:rootpass"
sn=8

# edit these to suit
countryName="/C=US"
stateOrProvinceName="/ST=IN"
localityName="/L=Change Me Locality"
organizationName="/O=Change me Organization"
organizationalUnitName="/OU=Devices"
commonName="/CN=Root CA"
DN=$countryName$stateOrProvinceName$localityName
export DN=$DN$organizationName$organizationalUnitName$commonName

echo $DN
export subjectAltName=email:whatever@happens.example.com

export default_crl_days=2048


