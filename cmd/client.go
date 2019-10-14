package main

import (
	"awesomedns/pkg"
	"log"
	"strconv"
)

func main() {
	q := []string{}
	for i := 0; i < 100; i++ {
		q = append(q, strconv.Itoa(i)+".ya.ru")
	}
	res, err := awesomedns.MegaBulkResolveA(q, awesomedns.Config{"77.88.8.8:53"})
	if err != nil {
		log.Print("err", err)
	}
	for k, v := range res {
		log.Println("result", k, v.Ips)
	}
}
