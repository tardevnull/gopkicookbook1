package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	//PKCS#1 format RSA PrivateKey [RFC8017]
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 DER encoded form
	derRsaPrivateKey := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	f, err := os.Create("derFormatRsaPrivate.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	_, err = f.Write(derRsaPrivateKey)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 PEM encoded form
	f, err = os.Create("pemFormatRsaPrivate.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derRsaPrivateKey})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//PKCS#1 format RSA PublicKey
	var rsaPublicKey crypto.PublicKey
	rsaPublicKey = rsaPrivateKey.Public()

	var derRsaPublicKey []byte
	//Convert to ASN.1 DER encoded form
	if rsaPublicKeyPointer, ok := rsaPublicKey.(*rsa.PublicKey); ok {
		derRsaPublicKey = x509.MarshalPKCS1PublicKey(rsaPublicKeyPointer)
	}
	f, err = os.Create("derFormatRsaPublic.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	_, err = f.Write(derRsaPublicKey)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 PEM encoded form
	f, err = os.Create("pemFormatRsaPublic.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: derRsaPublicKey})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to SubjectPublicKeyInfo RSA encryption
	//[RFC5280], [RFC3279], [RFC4055], [RFC4491]
	publicKeyInfo, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	//Convert to ASN.1 DER encoded form
	if err != nil {
		log.Fatalf("ERROR: converting Public Key Info: %v\n", err)
	}
	f, err = os.Create("subjectPublicKeyInfo.der")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	_, err = f.Write(publicKeyInfo)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 PEM encoded form
	f, err = os.Create("subjectPublicKeyInfo.pem")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyInfo})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//PKCS#8 format RSA PrivateKey [RFC5208]
	privateKeyInfo, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	f, err = os.Create("privateKeyInfo.der")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	_, err = f.Write(privateKeyInfo)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 PEM encoded form
	f, err = os.Create("privateKeyInfo.pem")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyInfo})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

}
