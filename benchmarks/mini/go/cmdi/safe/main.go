// MINI benchmark: go/cmdi (CWE-78) — safe variant（argv 直传、不经 shell、输入白名单）。
package main

import (
	"net/http"
	"os/exec"
	"regexp"
)

var safeArg = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func cmdiSafeHandler(w http.ResponseWriter, r *http.Request) {
	// Entry point: GET /cmdi?arg=<value>
	userInput := r.URL.Query().Get("arg")
	if !safeArg.MatchString(userInput) {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}
	cmd := exec.Command("echo", userInput) // SAFE: direct argv, no shell
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

func main() {
	http.HandleFunc("/cmdi", cmdiSafeHandler)
	_ = http.ListenAndServe(":8082", nil)
}
