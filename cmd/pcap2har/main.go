package main

import (
	"log"
	"os"

	jsoniter "github.com/json-iterator/go"

	"github.com/colinnewell/pcap-cli/cli"
	"github.com/colinnewell/pcap2har-go/internal/har"
	"github.com/colinnewell/pcap2har-go/internal/reader"
)

func main() {
	r := reader.New()
	cli.Main("", r, output)
}

func output(completed chan interface{}) {
	var har har.Har
	har.Log.Version = "1.2"
	har.Log.Creator.Name = "pcap2har"
	har.Log.Creator.Version = cli.Version

	for v := range completed {
		har.AddEntry(v.(reader.Conversation))
	}
	har.FinaliseAndSort()

	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	err := e.Encode(har)
	if err != nil {
		log.Println(err)
		return
	}
}
