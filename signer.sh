#!/bin/bash

openssl req -x509 -newkey rsa:2048 -keyout certificate.key -out certificate.crt -days 365 -nodes -subj "/C=US/ST=CA/L=LA/O=Org/OU=Unit/CN=Microsoft.com"

if [ -f "certificate.crt" ]; then
  echo "Self-signed certificate created successfully."
else
  echo "Certificate creation failed."
  exit 1
fi

openssl smime -sign -binary -signer certificate.crt -inkey certificate.key -in loader.dll -out signed_loader.dll

if [ -f "signed_loader.dll" ]; then
  echo "DLL signed successfully."
else
  echo "DLL signing failed."
  exit 1
fi

echo "Generated Certificate Information:"
openssl x509 -in certificate.crt -noout -text

rm certificate.key certificate.crt

echo "Script completed. Your DLL file should be signed and verified."
