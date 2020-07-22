package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/colinnewell/pcap2har-go/internal/go/fcgi"
)

func main() {
	files := os.Args[1:]

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}
	for _, filename := range files {
		r, err := os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		c := fcgi.NewChild(func(req *http.Request) {
			r, err := httputil.DumpRequest(req, true)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println(string(r))
			}
		})
		c.ReadRequest(r)
		// now grab the data
	}
}
