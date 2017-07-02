package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/urfave/cli"
)

const (
	version = "0.0.1"
	usage   = `Encrypt/Decrypt tool by the RSA encryption for your secret file.`
)

var (
	label = []byte("Encoded by Gocri(v" + version + ") RSA")
)

type(
	content struct {
		Path string `json:"path"`
		Body []byte `json:"body"`
	}
	secret struct {
		Contents []content `json:"contents"`
	}
)

func main() {
	app := cli.NewApp()
	app.Name = "Gocri"
	app.Usage = usage
	app.Version = version
	app.Commands = commands()

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func commands() []cli.Command {
	return []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "Encrypt your files",
			Description: `
      gocri encrypt filename... --key id_rsa.pub --output secret.out`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key, k",
					Usage: "Specify your public-key to encrypt",
				},
				cli.StringFlag{
					Name:  "output, o",
					Usage: "Specify an output filename",
				},
			},
			Action: encrypt,
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "Decrypt gocri's binary file",
			Description: `
      gocri decrypt --key id_rsa filename...`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key, k",
					Usage: "Specify your public-key to encrypt",
				},
			},
			Action: decrypt,
		},
	}
}

func encrypt(c *cli.Context) error {
	pub, err := readPublicKey(c)
	if err != nil {
		return publicKeyError(err)
	}

	var secret secret
	contents := make([]content, 0)
	l := c.NArg()
	for i := 0; i < l; i++ {
		path := c.Args().Get(i)
		body, err := readFile(path)
		if err != nil {
			return fileError(err, path)
		}
		contents = append(contents, content{
			Path: path,
			Body: body,
		})
	}

	secret.Contents = contents
	msg, err := json.Marshal(&secret)
	if err != nil {
		return cli.NewExitError("Failed to marshal to Json format.", 1)
	}

	rng := rand.Reader
	cipher, err := rsa.EncryptOAEP(sha256.New(), rng, pub, msg, label)
	if err != nil {
		return cli.NewExitError("Failed to encode your file(s) by RSA.", 1)
	}

	out := c.String("output")
	if len(out) > 0 {
		path, err := filepath.Abs(out)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("Underlying fs didn't provide absolute path of your file (%s)", out), 1)
		}
		if err = ioutil.WriteFile(path, cipher, 0644); err != nil {
			return cli.NewExitError(fmt.Sprintf("Failed to output to file('%s').", out), 1)
		}
	} else {
		if _, err = os.Stdout.Write(cipher); err != nil {
			return cli.NewExitError("Failed to output to stdout.", 1)
		}
	}

	return nil
}

func decrypt(c *cli.Context) error {
	priv, err := readPrivateKey(c)
	if err != nil {
		return publicKeyError(err)
	}

	l := c.NArg()
	for i := 0; i < l; i++ {
		path := c.Args().Get(i)
		body, err := readFile(path)
		if err != nil {
			return fileError(err, path)
		}

		rng := rand.Reader
		txt, err := rsa.DecryptOAEP(sha256.New(), rng, priv, body, label)

		var secret secret
		if err = json.Unmarshal(txt, &secret); err != nil {
			return cli.NewExitError("Failed to unmarsbal binary.", 1)
		}

		for _, content := range secret.Contents {
			out := content.Path
			path, err := filepath.Abs(out)
			if err != nil {
				return cli.NewExitError(fmt.Sprintf("Underlying fs didn't provide absolute path of a file (%s)", out), 1)
			}
			if err = ioutil.WriteFile(path, content.Body, 0644); err != nil {
				return cli.NewExitError(fmt.Sprintf("Failed to output to file('%s').", out), 1)
			}
		}
	}

	return nil
}
