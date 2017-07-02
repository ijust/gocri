package main

import (
	"os"
	"errors"
	"path/filepath"
	"io/ioutil"
	"fmt"
	"crypto/rsa"
	"encoding/pem"
	"crypto/x509"

	"github.com/urfave/cli"
)

func abs(filename string) (string, error) {
	path, err := filepath.Abs(filename)
	if err != nil {
		return "", errAbsFailed
	}

	if _, err = os.Stat(path); err != nil {
		return "", errFileNotFound
	}

	return path, nil
}

func readFile(filename string) ([]byte, error) {
	path, err := abs(filename)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to read your file (%s)", path))
	}

	return b, nil
}

func readKey(c *cli.Context, kind string) ([]byte, error) {
	key := c.String("key")
	if len(key) == 0 {
		return nil, errors.New(fmt.Sprintf("%s key is required.", kind))
	}

	path, err := abs(key)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func readPublicKey(c *cli.Context) (*rsa.PublicKey, error) {
	b, err := readKey(c, "Public")
	if err != nil {
		return nil, err
	}

	// TODO: Challenge parsing more formats.
	var p *pem.Block
	for {
		p, b = pem.Decode(b)
		if p == nil {
			return nil, errors.New("No PEM data is found")
		}
		if p.Type == "PUBLIC KEY" {
			break
		}
	}

	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	// TODO: Challenge to cast more encoding formats
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Not RSA Format data.")
	}

	return pk, nil
}

func readPrivateKey(c *cli.Context) (*rsa.PrivateKey, error) {
	b, err := readKey(c, "Private")
	if err != nil {
		return nil, err
	}

	// TODO: Challenge parsing more formats.
	var p *pem.Block
	for {
		p, b = pem.Decode(b)
		if p == nil {
			return nil, errors.New("No PEM data is found")
		}
		if p.Type == "RSA PRIVATE KEY" {
			break
		}
	}

	// TODO: Challenge to cast more encoding formats
	pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}
