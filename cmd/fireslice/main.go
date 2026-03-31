package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mojomast/fireslice/internal/dashboard"
	"github.com/mojomast/fireslice/internal/db"
	app "github.com/mojomast/fireslice/internal/fireslice"
	"github.com/mojomast/fireslice/internal/gateway"
	"github.com/mojomast/fireslice/internal/httpapi"
	"github.com/mojomast/fireslice/internal/proxy"
	"github.com/mojomast/fireslice/internal/sessionauth"
	"github.com/mojomast/fireslice/internal/vm"
)

func main() {
	cfg := app.DefaultConfig()
	cfg.RegisterFlags(flag.CommandLine)
	flag.Parse()

	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	logLevel := slog.LevelInfo
	if cfg.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer database.Close()

	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	var vmManager *vm.Manager
	vmManager, err = vm.NewManager(database, &vm.ManagerConfig{
		DataDir:        cfg.DataDir,
		FirecrackerBin: cfg.FirecrackerBin,
		KernelPath:     cfg.KernelPath,
		InitrdPath:     cfg.InitrdPath,
		BridgeName:     cfg.NetworkBridge,
		SubnetCIDR:     cfg.NetworkSubnet,
	}, logger.With("component", "vm"))
	if err != nil {
		logger.Warn("VM manager unavailable; continuing without provisioning support", "error", err)
		vmManager = nil
	}

	metaSrv := gateway.NewServer(cfg.MetadataAddr, logger.With("component", "metadata"))
	metaSrv.SetDB(database)

	proxyMgr := proxy.NewManager(&proxy.Config{
		AdminAPI: cfg.CaddyAdminAddr,
		Domain:   cfg.Domain,
	}, logger.With("component", "proxy"))
	if !proxyMgr.Healthy(ctx) {
		logger.Warn("Caddy admin API not reachable", "admin_api", cfg.CaddyAdminAddr)
	}
	if vmManager != nil {
		if err := vmManager.ReconcileVMRoutes(ctx, proxyMgr.RemoveRoute); err != nil {
			logger.Warn("failed to reconcile stale VM routes", "error", err)
		}
	}

	userStore := &app.DBUserStore{DB: database}
	vmStore := &app.DBVMStore{DB: database}
	auditStore := &app.DBAuditStore{DB: database}
	var vmRuntime app.VMRuntime
	if vmManager != nil {
		vmRuntime = &app.VMRuntimeAdapter{Runtime: vmManager, Users: userStore, VMs: vmStore}
	}
	service := app.NewService(userStore, vmStore, vmRuntime, proxyMgr)
	service.Audit = auditStore
	service.Images = app.NewFileImageStore(filepath.Join(cfg.DataDir, "images", "catalog.json"))

	var authMgr *sessionauth.Manager
	if cfg.AdminPassBcrypt != "" || userStore != nil {
		authMgr, err = sessionauth.New(&sessionauth.DBLookup{DB: database}, cfg.AdminUsername, cfg.AdminPassBcrypt, "fireslice_session", 24*time.Hour, false)
		if err != nil {
			log.Fatalf("init session auth: %v", err)
		}
	} else {
		logger.Warn("admin password hash not configured; login will be unavailable")
	}

	apiHandler := httpapi.New(service, httpapi.Options{})
	var dashboardHandler *dashboard.Handler
	if authMgr != nil {
		dashboardHandler, err = dashboard.New(service, authMgr, map[string]string{
			"domain":        cfg.Domain,
			"http_addr":     cfg.HTTPListenAddr,
			"db_path":       cfg.DBPath,
			"metadata_addr": cfg.MetadataAddr,
			"bridge":        cfg.NetworkBridge,
			"subnet":        cfg.NetworkSubnet,
		})
		if err != nil {
			log.Fatalf("init dashboard: %v", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithCancel(ctx)
	defer shutdownCancel()

	go func() {
		if err := metaSrv.Start(shutdownCtx); err != nil {
			logger.Error("metadata server exited", "error", err)
		}
	}()

	mux := http.NewServeMux()
	if authMgr != nil {
		apiHandler = httpapi.New(service, httpapi.Options{AuthMiddleware: authMgr.AuthMiddleware, AuditLogger: auditStore})
		dashboardHandler.Routes(mux)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "admin auth is not configured"})
		})
	}
	apiHandler.Routes(mux)

	httpSrv := &http.Server{
		Addr:    cfg.HTTPListenAddr,
		Handler: mux,
	}

	go func() {
		logger.Info("fireslice HTTP server listening", "addr", cfg.HTTPListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server exited", "error", err)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	<-done

	shutdownCancel()

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctxTimeout); err != nil {
		logger.Error("HTTP shutdown failed", "error", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
