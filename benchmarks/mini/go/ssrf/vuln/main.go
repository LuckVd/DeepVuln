// MINI benchmark: go/ssrf (CWE-918) — vulnerable variant.
//
// 链路：handler query 参数中的 URL（source）→ http.Get 出网请求（sink）。
package main

import (
	"io"
	"net/http"
)

func ssrfVulnHandler(w http.ResponseWriter, r *http.Request) {
	// Entry point: GET /fetch?url=<target>
	targetURL := r.URL.Query().Get("url")
	resp, err := http.Get(targetURL) // SINK: ssrf (CWE-918)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	_, _ = w.Write(body)
}

func main() {
	http.HandleFunc("/fetch", ssrfVulnHandler)
	_ = http.ListenAndServe(":8085", nil)
}
