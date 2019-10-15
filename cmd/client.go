package main

import (
	awesomedns "awesomedns/pkg"
	"log"
	"strconv"
)

func main() {
	var q []string
	for i := 0; i < 100; i++ {
		q = append(q, strconv.Itoa(i)+".ya.ru")
	}
	res, err := awesomedns.BulkResolveA(q, awesomedns.Config{"77.88.8.8:53", false})
	if err != nil {
		log.Print("err", err)
	}
	for k, v := range res {
		log.Println("result", k, v.Ips)
	}
}
