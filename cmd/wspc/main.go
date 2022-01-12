package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/gowsp/wsp/pkg/client"
)

func main() {
	config, err := parseConf()
	if err != nil {
		log.Println(err)
		return
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	client := client.Wspc{Config: config}
	go client.ListenAndServe()
	<-c
	log.Println("wspc closed")
}

func parseConf() (*client.Config, error) {
	configVar := flag.String("c", "wspc.json", "wspc config file")
	flag.Parse()
	file, err := os.Open(*configVar)
	if err != nil {
		return nil, err
	}
	conf, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var config client.Config
	err = json.Unmarshal(conf, &config)
	return &config, err
}