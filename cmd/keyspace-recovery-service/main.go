package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/base-org/keyspace-recovery-service/proving"
	"github.com/base-org/keyspace-recovery-service/proving/storage"
	recover_rpc "github.com/base-org/keyspace-recovery-service/rpc"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/urfave/cli/v2"
)

const Version = "v0.0.1"

func main() {
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelInfo, true)))

	app := cli.NewApp()
	app.Flags = Flags
	app.Version = Version
	app.Name = "keyspace-recovery-service"
	app.Description = "Keyspace Recovery Service"

	app.Action = curryMain(Version)
	err := app.Run(os.Args)
	if err != nil {
		log.Crit("Application failed", "error", err)
	}
}

func curryMain(version string) func(ctx *cli.Context) error {
	return func(ctx *cli.Context) error {
		return Main(version, ctx)
	}
}

func runServer(apis []rpc.API, portAddr string) (*http.Server, error) {
	handler := rpc.NewServer()

	if err := node.RegisterApis(apis, nil, handler); err != nil {
		return nil, fmt.Errorf("error registering APIs: %w", err)
	}

	serv := &http.Server{Addr: portAddr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/_health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		handler.ServeHTTP(w, r)
	})}
	log.Info("Starting HTTP server", "address", portAddr)
	go func() {
		err := serv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server failed", "error", err)
		}
	}()

	return serv, nil
}

func Main(version string, cliCtx *cli.Context) error {
	log.Info("Starting keyspace-recovery-service", "version", version)
	path, err := filepath.Abs(cliCtx.String(CircuitPathFlag.Name))
	if err != nil {
		return err
	}
	log.Info("Using local storage", "path", path)
	s := storage.NewFileStorage(path)
	loader := proving.NewLockingCircuitLoader(s)
	rpcService := recover_rpc.NewRecover(loader)
	recoveryAPI := rpc.API{
		Namespace: "recover",
		Service:   rpcService,
	}
	recoveryServer, err := runServer([]rpc.API{recoveryAPI}, fmt.Sprintf(":%d", cliCtx.Int(PortFlag.Name)))
	if err != nil {
		return err
	}

	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGQUIT)
	<-interruptChannel

	return recoveryServer.Shutdown(context.Background())
}
