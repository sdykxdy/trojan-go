package main

import (
	"flag"

	_ "github.com/faireal/trojan-go/component"
	"github.com/faireal/trojan-go/log"
	"github.com/faireal/trojan-go/option"
)

func main() {
	flag.Parse()
	for {
		h, err := option.PopOptionHandler()
		if err != nil {
			log.Fatal("invalid options")
		}
		err = h.Handle()
		if err == nil {
			break
		}
	}
}
