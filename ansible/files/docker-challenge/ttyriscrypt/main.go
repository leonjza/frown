package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ./makesecret.py
// flag is: flag{y0u_c4nt_h1d3_fr0m_fr333da}
var SECRET = []int{
	80, 89, 80, 83, 72, 31, 1, 77, 107, 86, 85, 11, 16, 111, 14, 87, 82, 3, 110, 82, 68,
	82, 14, 107, 2, 23, 10, 85, 80, 93, 4, 77,
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
