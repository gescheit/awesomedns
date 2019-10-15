package main

import (
	awesomedns "awesomedns/pkg"
	"log"
)

func main() {
	res, _, err := awesomedns.Resolve(awesomedns.RR_AXFR, "zonetransfer.me", awesomedns.Config{"81.4.108.41:53", true})
	if err != nil {
		log.Print("err", err)
	}
	for k, v := range res {
		log.Println("result", k, v)
	}
}
