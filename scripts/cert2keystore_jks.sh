#!/bin/bash

if [ -z $1 ]; then
  echo "Usage: cert2keystore_jks.sh <CA cert PEM file> <Password>"
  exit 1
fi

CACERT=$1
PASS=$2

TRUSTSTORE=bithertruststore.jks
ALIAS=`openssl x509 -inform PEM -subject_hash -noout -in $CACERT`

if [ -f $TRUSTSTORE ]; then
    rm $TRUSTSTORE || exit 1
fi

echo "Adding certificate to $TRUSTSTORE..."
keytool -import -v -trustcacerts -alias $ALIAS \
      -file $CACERT \
      -keystore $TRUSTSTORE \
      -storepass $PASS

echo "" 
echo "Added '$CACERT' with alias '$ALIAS' to $TRUSTSTORE..."

