package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func generateSKID(pk []byte) ([]byte, error) {
	var pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(pk, &pkixPublicKey); err != nil {
		return nil, err
	}
	skid := sha256.Sum256(pkixPublicKey.BitString.Bytes)
	return skid[:], nil
}

func GetSKIDFromCert(cert string) {
	c, err := os.ReadFile(cert)
	if err != nil {
		log.Fatal(err)
	}
	cd, _ := pem.Decode(c)
	cert509, err := x509.ParseCertificate(cd.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(cert509.SubjectKeyId))
}

func GetSKIDFromKey(key string) {
	c, err := os.ReadFile(key)
	if err != nil {
		log.Fatal(err)
	}
	cd, _ := pem.Decode(c)

	key509, err := x509.ParsePKCS8PrivateKey(cd.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	var kb []byte
	switch ke := key509.(type) {
	case *rsa.PrivateKey:
		kb, _ = x509.MarshalPKIXPublicKey(ke.Public())
	case *ecdsa.PrivateKey:
		kb, _ = x509.MarshalPKIXPublicKey(ke.Public())
	case *ecdh.PrivateKey:
		kb, _ = x509.MarshalPKIXPublicKey(ke.Public())
	case ed25519.PrivateKey:
		kb, _ = x509.MarshalPKIXPublicKey(ke.Public())
	default:
		log.Fatal("key type error")
	}
	skid, err := generateSKID(kb)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(skid))
}

func main() {
	var certPath string
	var keyPath string

	flag.StringVar(&certPath, "cert", "", "Get SKID from the cert")
	flag.StringVar(&keyPath, "key", "", "Get SKID from the private key")
	flag.Parse()

	if certPath == "" && keyPath == "" {
		log.Fatal("no cert or no key")
	}
	switch {
	case certPath != "":
		GetSKIDFromCert(certPath)
	case keyPath != "":
		GetSKIDFromKey(keyPath)
	}
}
