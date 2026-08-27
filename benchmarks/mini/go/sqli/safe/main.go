// MINI benchmark: go/sqli (CWE-89) — safe variant（占位符参数化查询）。
package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func sqliSafeHandler(w http.ResponseWriter, r *http.Request) {
	// Entry point: GET /user?id=<uid>
	userID := r.URL.Query().Get("id")
	query := "SELECT name FROM users WHERE id = ?"
	row := db.QueryRow(query, userID) // SAFE: parameterized query
	var name string
	if err := row.Scan(&name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(name))
}

func main() {
	http.HandleFunc("/user", sqliSafeHandler)
	_ = http.ListenAndServe(":8084", nil)
}
