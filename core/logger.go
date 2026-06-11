package core

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func InitLogger() {
	if err := os.MkdirAll("logs", 0o755); err != nil {
		log.Printf("create log dir failed: %v", err)
	}
	file, err := os.OpenFile("logs/agent.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("open log file failed: %v", err)
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.MultiWriter(os.Stdout, file))
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("logger initialized")
}

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
