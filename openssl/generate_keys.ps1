## This script will generate fresh pair of private/public keys in PKCS8 and PKCS1 formats.

# generate PKCS#8 keys and export public key
openssl genrsa -out private-key.pem 2048
openssl rsa -in private-key.pem -pubout -out public-key.pem

# convert to PKCS#1
openssl pkey -in private-key.pem -out private-key-pkcs1.pem -traditional
openssl rsa -pubin -in public-key.pem -RSAPublicKey_out -out public-key-pkcs1.pem