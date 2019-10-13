package awesomedns
// наивная реализация массового режима
// вывываем Resolve на каждый запрос
import (
	"log"
	"net"
)

type workerAnswer struct {
	query string
	answer []net.IP
	err error
}

type Answer struct {
	Answer []net.IP
	Err error
}

func worker(config Config,q chan string, res chan workerAnswer)  {
	for {
		fqdn, ok := <-q
		if ok == false {
			break
		}
		a, err := ResolveA(fqdn, config)
		res <- workerAnswer{fqdn, a, err}
	}
}

func BulkResolveA(req []string, config Config) (map[string]Answer, error) {
	var res = map[string]Answer{}
	workers := 2
	reqs := make(chan string, 10)
	defer close(reqs)
	ans := make(chan workerAnswer, 10)
	defer close(ans)
	// запуск n-воркеров
	for w:=0; w<workers; w++ {
		go worker(config, reqs, ans)
	}

	for _, fqdn := range req{
		log.Println("send", fqdn)
		reqs<-fqdn
	}

	for i:=0; i<len(req); i++ {
		a := <- ans
		res[a.query] = Answer{a.answer, a.err}
		log.Printf("recv %v", a)
	}
	log.Println("done", res)

	return res, nil
}
