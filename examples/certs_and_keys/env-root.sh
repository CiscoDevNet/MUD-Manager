##############################################################################
# The content of this file is taken from the "Guide for building an ECC pki"
# draft available at
# https://datatracker.ietf.org/doc/draft-moskowitz-ecdsa-pki/?include_text=1
##############################################################################

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

export cadir=${cadir-/root/ca}
export rootca=${cadir}/root
export cfgdir=${cfgdir-$cadir}
export intdir=${cadir}/intermediate
export int1ardir=${cadir}/inter_1ar
export format=pem
export default_crl_days=65

mkdir -p $cadir/certs
mkdir -p $rootca
(cd $rootca
mkdir -p certs crl csr newcerts private
chmod 700 private
touch index.txt index.txt.attr
if [ ! -f serial ]; then echo 00 >serial; fi
)

sn=8

# edit these to suit
countryName="/C=US"
stateOrProvinceName="/ST=IN"
localityName="/L=Indiana University"
organizationName="/O=Cisco"
organizationalUnitName="/OU=Devices"
commonName="/CN=Root CA"
DN=$countryName$stateOrProvinceName$localityName
export DN=$DN$organizationName$organizationalUnitName$commonName

echo $DN
export subjectAltName=email:postmaster@htt-consult.com

export default_crl_days=2048


