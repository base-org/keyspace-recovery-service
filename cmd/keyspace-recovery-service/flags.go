package main

import (
	"github.com/urfave/cli/v2"
)

const envVarPrefix = "RECOVERY_SERVICE"

func PrefixEnvVar(suffix string) []string {
	return []string{envVarPrefix + "_" + suffix}
}

var (
	PortFlag = &cli.IntFlag{
		Name:    "port",
		Usage:   "Port to run the RPC service on",
		EnvVars: PrefixEnvVar("PORT"),
		Value:   8555,
	}
	CircuitPathFlag = &cli.StringFlag{
		Name:    "circuit-path",
		Usage:   "Path to the compiled circuit files",
		EnvVars: PrefixEnvVar("CIRCUIT_PATH"),
		Value:   "compiled/",
	}
)

var Flags = []cli.Flag{
	PortFlag,
	CircuitPathFlag,
}
