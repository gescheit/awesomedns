package main

import (
	"awesomedns/pkg"
)

func main() {
	awesomedns.BulkResolveA([]string{"ya.ru", "ne.ya.ru"}, awesomedns.Config{"77.88.8.8:53"})
}
