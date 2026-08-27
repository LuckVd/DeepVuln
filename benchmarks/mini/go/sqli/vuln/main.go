// MINI benchmark: go/sqli (CWE-89) — vulnerable variant.
//
// 链路：handler query 参数（source）→ fmt.Sprintf 拼 SQL → db.QueryRow（sink）。
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

func sqliVulnHandler(w http.ResponseWriter, r *http.Request) {
	// Entry point: GET /user?id=<uid>
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", userID)
	row := db.QueryRow(query) // SINK: sql-injection (CWE-89)
	var name string
	if err := row.Scan(&name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(name))
}

func main() {
	http.HandleFunc("/user", sqliVulnHandler)
	_ = http.ListenAndServe(":8083", nil)
}
