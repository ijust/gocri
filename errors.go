package main

import (
	"fmt"
	"errors"

	"github.com/urfave/cli"
)

var (
	errAbsFailed = errors.New("Failed to absolute path")
	errFileNotFound = errors.New("File Not Found")
)

func publicKeyError(err error) *cli.ExitError {
	switch err {
	case errAbsFailed:
		return cli.NewExitError("Underlying fs didn't provide absolute path of your public key", 1)
	case errFileNotFound:
		return cli.NewExitError("Public key was not found.", 1)
	}
	return cli.NewExitError(err.Error(), 1)
}

func fileError(err error, filename string) *cli.ExitError {
	switch err {
	case errAbsFailed:
		return cli.NewExitError(fmt.Sprintf("Underlying fs didn't provide absolute path of your file (%s)", filename), 1)
	case errFileNotFound:
		return cli.NewExitError(fmt.Sprintf("File (%s) was not found.", filename), 1)
	}
	return cli.NewExitError(err.Error(), 1)
}