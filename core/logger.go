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
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		log.Printf("http %s %s status=%d bytes=%d remote=%s duration=%s", r.Method, r.URL.Path, recorder.status, recorder.bytes, r.RemoteAddr, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}
