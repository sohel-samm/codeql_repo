package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

// 1. Hardcoded secret (CWE-798)
const API_KEY = "hardcoded-secret-12345"

func main() {
	http.HandleFunc("/user", sqlInjection)
	http.HandleFunc("/ping", commandInjection)
	http.HandleFunc("/read", pathTraversal)
	http.HandleFunc("/greet", xss)
	http.HandleFunc("/debug", infoLeak)

	fmt.Println("Vulnerable Go app running on :8080")
	http.ListenAndServe(":8080", nil)
}

// 2. SQL Injection (CWE-89)
func sqlInjection(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	db, _ := sql.Open("sqlite3", "./test.db")
	query := "SELECT * FROM users WHERE name = '" + username + "'" // ❌ vulnerable
	rows, _ := db.Query(query)
	defer rows.Close()

	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "User: %s\n", name)
	}
}

// 3. Command Injection (CWE-78)
func commandInjection(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output() // ❌ vulnerable
	w.Write(out)
}

// 4. Path Traversal (CWE-22)
func pathTraversal(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	data, _ := ioutil.ReadFile(file) // ❌ vulnerable
	w.Write(data)
}

// 5. Cross-Site Scripting (XSS) (CWE-79)
func xss(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name) // ❌ unsanitized user input
}

// 6. Information Exposure (CWE-200)
func infoLeak(w http.ResponseWriter, r *http.Request) {
	for _, e := range os.Environ() { // ❌ leaks environment variables
		fmt.Fprintln(w, e)
	}
}
