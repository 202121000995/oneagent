package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nodetoolsagent/core"
)

func main() {
	core.InitLogger()

	cfg, err := core.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := core.InitDatabase("database/nodetools.db")
	if err != nil {
		log.Fatalf("init database: %v", err)
	}
	defer db.Close()

	auth := core.NewAuth(db)
	if err := auth.EnsureAdmin(cfg.Server.AdminUser, cfg.Server.AdminPass); err != nil {
		log.Fatalf("init auth: %v", err)
	}
	if cfg.Server.AdminPass != "" {
		cfg.Server.AdminPass = ""
	}
	if err := core.SaveConfig("config.yaml", cfg); err != nil {
		log.Printf("save normalized config failed: %v", err)
	}

	manager := core.NewManager(db, "config.yaml")
	if err := manager.ApplyConfig(cfg); err != nil {
		log.Fatalf("apply config: %v", err)
	}
	manager.StartTrafficSampler()
	defer manager.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go core.WatchConfig(ctx, "config.yaml", 2*time.Second, func(next core.Config) {
		if err := manager.ApplyConfig(next); err != nil {
			log.Printf("hot reload failed: %v", err)
			return
		}
		auth.Refresh(next.Server.AdminUser, next.Server.AdminPass)
		log.Println("configuration hot reloaded")
	})

	mux := http.NewServeMux()
	core.RegisterAPI(mux, manager, auth)
	core.RegisterWeb(mux, "web", auth)

	addr := ":" + strconv.Itoa(cfg.Server.WebPort)
	server := &http.Server{
		Addr:              addr,
		Handler:           core.RequestLogger(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("NodeTools Agent started on http://0.0.0.0%s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown failed: %v", err)
	}
}
