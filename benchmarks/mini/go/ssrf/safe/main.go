// MINI benchmark: go/ssrf (CWE-918) — safe variant（目标 URL 前缀白名单校验）。
package main

import (
	"io"
	"net/http"
	"strings"
)

const allowedBase = "https://api.internal.example.com/"

func ssrfSafeHandler(w http.ResponseWriter, r *http.Request) {
	// Entry point: GET /fetch?url=<target>
	targetURL := r.URL.Query().Get("url")
	if !strings.HasPrefix(targetURL, allowedBase) { // SAFE: allowlist check
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	_, _ = w.Write(body)
}

func main() {
	http.HandleFunc("/fetch", ssrfSafeHandler)
	_ = http.ListenAndServe(":8086", nil)
}
