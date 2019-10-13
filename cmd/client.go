package main

import (
	"awesomedns/pkg"
	"log"
)

func main() {
	res, err := awesomedns.MegaBulkResolveA([]string{"ya.ru", "ne.ya.ru", "google.com"}, awesomedns.Config{"77.88.8.8:53"})
	if err != nil{
		log.Print("err", err)
	}
	for k, v := range res{
		log.Println("result", k, v.Answer)
	}
}
