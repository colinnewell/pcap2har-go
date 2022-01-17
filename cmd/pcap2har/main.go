package main

import (
	"io"
	"log"

	jsoniter "github.com/json-iterator/go"

	"github.com/colinnewell/pcap-cli/cli"
	"github.com/colinnewell/pcap2har-go/internal/har"
	"github.com/colinnewell/pcap2har-go/internal/reader"
)

func main() {
	r := reader.New()
	cli.Main("", r, output(r))
}

func output(r *reader.HTTPConversationReaders) func(io.Writer, chan interface{}) {
	return func(w io.Writer, completed chan interface{}) {
		var har har.Har
		har.Log.Version = "1.2"
		har.Log.Creator.Name = "pcap2har"
		har.Log.Creator.Version = cli.Version

		<-completed

		c := r.GetConversations()
		for _, v := range c {
			har.AddEntry(v)
		}
		har.FinaliseAndSort()

		var json = jsoniter.ConfigCompatibleWithStandardLibrary
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		err := e.Encode(har)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
