package awesomedns

import (
	"log"
	"net"
	"time"
)

type writerTask struct {
	transactionId int
	fqdn          string
}

type readerTask struct {
	transactionId int
	answer        Answer
}

type waitStatus struct {
	fqdn string
	sent time.Time
	ok   bool
}

func extractIp(items []interface{}) []net.IP {
	var res = []net.IP{}
	for _, item := range items {
		switch item.(type) {
		case net.IP:
			res = append(res, item.(net.IP))
		}
	}
	return res
}

func connWriter(req chan writerTask, conn net.Conn, rate int) {
	if rate > 1_000_000 {
		rate = 1_000_000
	}

	period := time.Duration(1_000_000_000 / rate) // nano

	for {
		task, ok := <-req
		if ! ok {
			return
		}
		log.Println("send", task)
		q, err := makeQuery(RR_A, task.fqdn, task.transactionId)
		if err != nil {
			log.Printf("makeQuery to %v", task.fqdn)
		}
		// простая реализация выдерживание периода
		time.Sleep(period)
		_, err = conn.Write(q)
		if err != nil {
			log.Printf("unable to send %v %v", err)
		}
	}
}

func connReader(answers chan readerTask, conn net.Conn) {
	buffer := make([]byte, 1024)
	for {
		_, err := conn.Read(buffer)
		if err != nil {
			log.Printf("unable to read %v", err)
		} else {
			ret, transactionId, err := parseDnsAnswer(buffer)
			if err != nil {
				log.Printf("unable to parse %v %v", buffer, err)
			} else {
				log.Printf("recv %v %v %v", ret, transactionId, err)
			}
			answers <- readerTask{transactionId, Answer{extractIp(ret), err}}
		}
	}
}

func MegaBulkResolveA(req []string, config Config) (map[string]Answer, error) {
	rate := 2    //pps
	timeout := 10 // s
	var res = map[string]Answer{}
	var inwait = map[int]*waitStatus{} // отслеживание статуса запроса. нужно для перепосылки

	conn, err := net.Dial("udp", config.Server)
	if err != nil {
		return res, err
	}

	writerCh := make(chan writerTask, 10)
	defer close(writerCh)
	readerCh := make(chan readerTask, 10)
	defer close(readerCh)

	go connWriter(writerCh, conn, rate)
	go connReader(readerCh, conn)

	for i, fqdn := range req {
		inwait[i] = &waitStatus{fqdn, time.Time{}, false}
	}
	for {
		if len(inwait) == 0 {
			break
		}
		for k, v := range inwait {
			if time.Now().Sub(v.sent) > time.Duration(timeout)*time.Second {
				writerCh <- writerTask{k, v.fqdn}
				v.sent = time.Now()
			}
		}
		select {
		case msg := <-readerCh:
			q, ok := inwait[msg.transactionId]
			if ! ok {
				log.Printf("received unknown msg %v", msg.transactionId)
			} else {
				delete(inwait, msg.transactionId)
				res[q.fqdn] = msg.answer
			}
		case <-time.After(1 * time.Second):
		}

	}
	return res, nil
}
