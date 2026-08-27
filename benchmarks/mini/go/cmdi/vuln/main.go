// MINI benchmark: go/cmdi (CWE-78) — vulnerable variant.
//
// 模式来源：Contrast-Security-OSS/go-test-bench 同型 taint 流。
// 链路：net/http handler query 参数（source）→ exec.Command 经 shell（sink）。
package main

import (
	"net/http"
	"os/exec"
)

func cmdiVulnHandler(w http.ResponseWriter, r *http.Request) {
	// Entry point: GET /cmdi?arg=<value>
	userInput := r.URL.Query().Get("arg")
	cmd := exec.Command("sh", "-c", "echo "+userInput) // SINK: command-injection (CWE-78)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

func main() {
	http.HandleFunc("/cmdi", cmdiVulnHandler)
	_ = http.ListenAndServe(":8081", nil)
}
