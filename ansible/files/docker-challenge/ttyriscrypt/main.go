package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ./makesecret.py
// flag is: flag{y0u_c4nt_h1d3_fr0m_fr333da}
var SECRET = []int{
	80, 89, 80, 83, 72, 31, 1, 77, 107, 86, 85, 11, 16, 111, 14, 87, 82, 3, 110, 82, 68,
	82, 14, 107, 2, 23, 10, 85, 80, 93, 4, 77,
}

func main() {

	// read the key from stdin. answer is: 65143f1845aed0ff60146bc4de9fc9e0
	reader := bufio.NewReader(os.Stdin)
	key, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("could not read key")
		return
	}

	if len(key) < 32 {
		fmt.Println("key too short")
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

	fmt.Printf("%s\n", flag.String())
}
