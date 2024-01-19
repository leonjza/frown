package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ./makesecret.py
// flag is: INS{y0u_c4nt_h1d3_fr0m_fr333da}
var SECRET = []int{
	127, 123, 98, 79, 74, 86, 68, 103, 87, 1, 15, 17, 59, 88, 87, 2, 5, 111, 87, 70, 6, 15,
	60, 82, 22, 86, 10, 85, 7, 88, 24,
}

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("[%s] %s %s from %s\n", t, r.Method, r.URL.Path, r.RemoteAddr)

		if r.Method != http.MethodPost {
			http.Error(w, "only posts please", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}

		// answer is: 65143f1845aed0ff60146bc4de9fc9e0
		key := string(body)

		if len(key) < 32 {
			http.Error(w, "key too short", http.StatusUnprocessableEntity)
			return
		}

		if len(key) > 32 {
			key = key[:32]
		}

		xord := make([]int, len(SECRET))
		for i, v := range SECRET {
			xord[i] = v ^ int(key[i%len(key)])
		}

		var flag strings.Builder
		for _, n := range xord {
			flag.WriteRune(rune(n))
		}

		fmt.Printf("[%s] key: %s, res: %s\n", t, key, flag.String())

		w.Header().Set("Content-Type", "text/plain")
		_, err = w.Write([]byte(flag.String()))
		if err != nil {
			fmt.Printf("Error writing response: %v", err)
		}
	})

	fmt.Println("Server starting on port 80...")
	http.ListenAndServe(":80", nil)
}
