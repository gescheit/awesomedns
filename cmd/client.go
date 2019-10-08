package main

import (
	"awesomedns/pkg"
	"fmt"
	"reflect"
)

func main() {
	res, err := awesomedns.ResolveAny("yandex-team.ru", awesomedns.Config{"77.88.8.8:53"})
	if err == nil {
		for _, item := range res {
			fmt.Println("----",reflect.TypeOf(item), item)
		}
	} else {

		fmt.Println("error", err)

	}
}
