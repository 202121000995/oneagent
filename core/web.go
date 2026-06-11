package core

import "net/http"

func RegisterWeb(mux *http.ServeMux, root string, auth *Auth) {
	mux.Handle("/static/", http.FileServer(http.Dir(root)))
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if auth.IsAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.ServeFile(w, r, root+"/templates/login.html")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/" {
			http.ServeFile(w, r, root+"/templates/dashboard.html")
			return
		}
		http.FileServer(http.Dir(root)).ServeHTTP(w, r)
	})
}
