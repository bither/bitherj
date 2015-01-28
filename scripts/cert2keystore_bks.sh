#!/bin/bash

if [ -z $1 ]; then
  echo "Usage: cert2keystore_bks.sh <CA cert PEM file> <Password>"
  exit 1
fi

CACERT=$1
PASS=$2
BCJAR=bcprov-jdk15on-146.jar

TRUSTSTORE=bithertruststore.bks
ALIAS=`openssl x509 -inform PEM -subject_hash -noout -in $CACERT`

if [ -f $TRUSTSTORE ]; then
    rm $TRUSTSTORE || exit 1
fi

echo "Adding certificate to $TRUSTSTORE..."
keytool -import -v -trustcacerts -alias $ALIAS \
      -file $CACERT \
      -keystore $TRUSTSTORE -storetype BKS \
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
      -providerpath $BCJAR \
      -storepass $PASS

echo "" 
echo "Added '$CACERT' with alias '$ALIAS' to $TRUSTSTORE..."

