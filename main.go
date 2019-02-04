//
// main.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os/user"
	"path"
	"syscall"
	"time"

	"github.com/fullsailor/pkcs7"
	"golang.org/x/crypto/ssh/terminal"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	keyBits = 4096
)

func main() {
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128GCM

	keygen := flag.String("keygen", "", "Create a keypair for argument email")
	encrypt := flag.Bool("encrypt", false, "Encrypt data")
	decrypt := flag.Bool("decrypt", false, "Decrypt data")
	message := flag.String("message", "", "Message to encrypt")
	id := flag.String("id", "", "The identity file PCKS#12")
	flag.Parse()

	if len(*keygen) > 0 {
		passphrase, err := ReadPassphrase("Passphrase", true)
		if err != nil {
			log.Fatal(err)
		}
		err = makeKey(string(passphrase), *keygen)
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	if *encrypt {
		if len(*message) == 0 {
			fmt.Printf("No message to encrypt\n")
			return
		}
		if len(flag.Args()) == 0 {
			fmt.Printf("No recipient certificates\n")
			return
		}
		var recipients []*x509.Certificate
		for _, arg := range flag.Args() {
			data, err := ioutil.ReadFile(arg)
			if err != nil {
				fmt.Printf("Failed to read recipient certificate '%s': %s\n",
					arg, err)
				return
			}
			cert, err := x509.ParseCertificate(data)
			if err != nil {
				fmt.Printf("Failed to parse recipient certificate '%s': %s\n",
					arg, err)
			}
			recipients = append(recipients, cert)
		}

		data, err := pkcs7.Encrypt([]byte(*message), recipients)
		if err != nil {
			fmt.Printf("Failed to encrypt message: %s\n", err)
			return
		}
		fmt.Printf("Encrypted message:\n%s\n",
			base64.StdEncoding.EncodeToString(data))
		return
	}

	if *decrypt {
		if len(*message) == 0 {
			fmt.Printf("No message to decrypt\n")
			return
		}
		data, err := base64.StdEncoding.DecodeString(*message)
		if err != nil {
			fmt.Printf("Failed to parse message Base64: %s\n", err)
			return
		}
		p7, err := pkcs7.Parse(data)
		if err != nil {
			fmt.Printf("Failed to parse message PKCS#7: %s\n", err)
			return
		}
		priv, cert, err := loadID(*id)
		if err != nil {
			fmt.Printf("Failed to load ID '%s': %s\n", *id, err)
			return
		}
		data, err = p7.Decrypt(cert, priv)
		if err != nil {
			fmt.Printf("Failed to decrypt message: %s\n", err)
			fmt.Printf("Content: %s\n", string(p7.Content))
			return
		}

		fmt.Printf("Message: %s\n", string(data))
		return
	}

	flag.Usage()
}

func loadID(file string) (crypto.PrivateKey, *x509.Certificate, error) {
	if len(file) == 0 {
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		file = path.Join(u.HomeDir, ".smime", "smime.p12")
	}
	passphrase, err := ReadPassphrase(fmt.Sprintf("Passphrase for ID '%s'",
		file), false)
	if err != nil {
		return nil, nil, err
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	priv, cert, err := pkcs12.Decode(data, string(passphrase))
	if err != nil {
		return nil, nil, err
	}
	key, ok := priv.(crypto.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("Invalid private key: %v", priv)
	}
	return key, cert, nil
}

func makeKey(passphrase, email string) error {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}

	subject := pkix.Name{
		Organization: []string{"ssh.com"},
		CommonName:   email,
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	now := time.Now()

	cert := &x509.Certificate{
		SerialNumber: serial,
		Issuer:       subject,
		Subject:      subject,
		NotBefore:    now.Add(time.Hour * 24 * -10),
		NotAfter:     now.Add(time.Hour * 24 * 365 * 5),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageEmailProtection,
		},
		EmailAddresses: []string{"markku.rossi@ssh.com"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert,
		&key.PublicKey, key)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fmt.Sprintf("%s.crt", email), certBytes, 0644)
	if err != nil {
		return err
	}

	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	data, err := pkcs12.Encode(rand.Reader, key, cert, nil, passphrase)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fmt.Sprintf("%s.p12", email), data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func ReadPassphrase(prompt string, confirm bool) ([]byte, error) {
	for {
		fmt.Printf("%s: ", prompt)
		first, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if err != nil {
			return nil, err
		}
		if !confirm {
			return first, nil
		}

		fmt.Print("Enter same passphrase again: ")
		second, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(first, second) {
			fmt.Print("Passphrases do not match\n")
			continue
		}
		return first, nil
	}
}
