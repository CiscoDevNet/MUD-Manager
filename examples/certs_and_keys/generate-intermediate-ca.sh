##############################################################################
# The content of this file is taken from the "Guide for building an ECC pki"
# draft available at
# https://datatracker.ietf.org/doc/draft-moskowitz-ecdsa-pki/?include_text=1
##############################################################################

# Create passworded keypair file

openssl genpkey -aes256 -algorithm ec\
   -pkeyopt ec_paramgen_curve:prime256v1 \
   -outform $format -pkeyopt ec_param_enc:named_curve\
   -out $dir/private/8021ARintermediate.key.$format
chmod 400 $dir/private/8021ARintermediate.key.$format
openssl pkey -inform $format\
   -in $dir/private/8021ARintermediate.key.$format -text -noout

# Create the CSR

openssl req -config $cadir/openssl-root.cnf\
   -key $dir/private/8021ARintermediate.key.$format \
   -keyform $format -outform $format -subj "$DN" -new -sha256\
   -out $dir/csr/8021ARintermediate.csr.$format
openssl req -text -noout -verify -inform $format\
   -in $dir/csr/8021ARintermediate.csr.$format

# Create 802.1AR Intermediate Certificate file
# The following does NOT work for DER

openssl rand -hex $sn > $dir/serial # hex 8 is minimum, 19 is maximum
# Note 'openssl ca' does not support DER format
openssl ca -config $cadir/openssl-root.cnf -days 3650\
   -extensions v3_intermediate_ca -notext -md sha256\
   -in $dir/csr/8021ARintermediate.csr.$format\
   -out $dir/certs/8021ARintermediate.cert.pem

chmod 444 $dir/certs/8021ARintermediate.cert.$format

openssl verify -CAfile $cadir/certs/ca.cert.$format\
    $dir/certs/8021ARintermediate.cert.$format

openssl x509 -noout -text\
    -in $dir/certs/8021ARintermediate.cert.$format

# Create the certificate chain file

cat $dir/certs/8021ARintermediate.cert.$format\
  $cadir/certs/ca.cert.$format > $dir/certs/ca-chain.cert.$format
chmod 444 $dir/certs/ca-chain.cert.$format
