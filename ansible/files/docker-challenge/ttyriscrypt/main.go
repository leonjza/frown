package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ./makesecret.py
// flag is: INS{f1rst_yoU_try_AND_hide_AnD_s0m3t1m3s_You_ARE_lucky}
var SECRET = []int{
	44, 122, 50, 25, 2, 0, 69, 23, 76, 105, 75, 86, 101, 103, 70, 23, 29, 60,
	115, 45, 125, 59, 12, 90, 92, 6, 59, 112, 88, 37, 106, 16, 85, 89, 82, 22,
	85, 92, 4, 23, 103, 111, 93, 76, 111, 121, 96, 32, 59, 15, 71, 0, 82, 29, 25,
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

		// answer is: e4abd17d8629082edc2c9dd38cd16a5c
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
