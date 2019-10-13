package awesomedns

import (
	"context"
	"log"
	"net"
	"time"
)

type waitStatus struct {
	fqdn string
	sent time.Time
	ok   bool
}

func extractIp(items []interface{}) []net.IP {
	var res []net.IP
	for _, item := range items {
		switch item.(type) {
		case net.IP:
			res = append(res, item.(net.IP))
		}
	}
	return res
}

func connWriter(req chan []byte, conn net.Conn, rate int, ctx context.Context) {
	if rate > 1_000_000 {
		rate = 1_000_000
	}

	period := time.Duration(1_000_000_000 / rate) // nano

	for {
		select {
		case <-ctx.Done():  // if cancel() execute
			return
		default:
		}
		msg, ok := <-req
		if ! ok {
			return
		}
		writen, err := conn.Write(msg)
		if writen != len(msg) || err != nil {
			log.Printf("unable to send %v err=%v", msg, err)
		}
		// простая реализация выдерживание периода
		time.Sleep(period)
	}
}

func connReader(answers chan []byte, conn net.Conn, ctx context.Context) {
	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():  // if cancel() execute
			return
		default:
		}
		read, err := conn.Read(buffer)
		if err != nil {
			log.Printf("unable to read %v", err)
		} else {
			tmp := make([]byte, read)
			copy(tmp, buffer)
			answers <- tmp
		}
	}
}

func MegaBulkResolveA(req []string, config Config) (map[string]Answer, error) {
	rate := 15     // pps
	timeout := 10 // s
	var res = map[string]Answer{}
	var inwait = map[int]*waitStatus{} // отслеживание статуса запроса. нужно для перепосылки
	ctx, cancel := context.WithCancel(context.Background())

	conn, err := net.Dial("udp", config.Server)
	if err != nil {
		return res, err
	}
	//conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	writerCh := make(chan []byte, 10)
	defer close(writerCh)
	readerCh := make(chan []byte, 10)
	defer close(readerCh)

	go connWriter(writerCh, conn, rate, ctx)
	go connReader(readerCh, conn, ctx)

	for i, fqdn := range req {
		inwait[i] = &waitStatus{fqdn, time.Time{}, false}
	}
	for {
		if len(inwait) == 0 {
			break
		}
		for k, v := range inwait {
			if time.Now().Sub(v.sent) > time.Duration(timeout)*time.Second {
				qmsg, err := makeQuery(RR_A, v.fqdn, k)
				if err != nil {
					log.Printf("makeQuery error %v for %v", err, v)
					continue
				}
				writerCh <- qmsg
				v.sent = time.Now()
			}
		}
		select {
		case msg := <-readerCh:
			ret, transactionId, err := parseDnsAnswer(msg)
			if err != nil {
				if err == errNameError{
				} else {
					log.Printf("unable to parse %v %v", msg, err)
				}
			} else {
				log.Printf("recv %v %v %v", ret, transactionId, err)
			}
			q, ok := inwait[transactionId]
			if ! ok {
				log.Printf("received unknown msg with transactionId=%v", transactionId)
			} else {
				delete(inwait, transactionId)
				res[q.fqdn] = Answer{extractIp(ret), err}
			}
		case <-time.After(1 * time.Second):
		}

	}
	cancel()
	return res, nil
}
