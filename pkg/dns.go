package awesomedns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"
)

func ResolveA(qname string, config Config) ([]net.IP, error) {
	var ret []net.IP
	res, _, err := Resolve(RR_A, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case net.IP:
			ret = append(ret, v.(net.IP))
		case string:
			//log.Printf("cname received %v", v)
		default:
			return nil, errors.New("unknown")
		}
	}
	return ret, nil
}

func ResolveAaaa(qname string, config Config) ([]net.IP, error) {
	var ret []net.IP
	res, _, err := Resolve(RR_AAAA, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case net.IP:
			ret = append(ret, v.(net.IP))
		default:
			return nil, errors.New("unknown")
		}
	}
	return ret, nil
}

func ResolveCname(qname string, config Config) ([]string, error) {
	var ret []string
	res, _, err := Resolve(RR_CNAME, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case string:
			ret = append(ret, v.(string))
		default:
			return nil, fmt.Errorf("unknown type - %v", v)
		}
	}
	return ret, nil
}

func Resolve_NS(qname string, config Config) ([]string, error) {
	var ret []string
	res, _, err := Resolve(RR_NS, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case string:
			ret = append(ret, v.(string))
		default:
			return nil, fmt.Errorf("unknown type - %v", v)
		}
	}
	return ret, nil
}

func ResolveSoa(qname string, config Config) ([]DnsSoa, error) {
	var ret []DnsSoa
	res, _, err := Resolve(RR_SOA, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case DnsSoa:
			ret = append(ret, v.(DnsSoa))
		default:
			return nil, fmt.Errorf("unknown type - %v with value %v", reflect.TypeOf(v), v)
		}
	}
	return ret, nil
}

func ResolvePtr(qname string, config Config) ([]string, error) {
	var ret []string
	qname += ".in-addr.arpa"
	res, _, err := Resolve(RR_PTR, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case string:
			ret = append(ret, v.(string))
		default:
			return nil, fmt.Errorf("unknown type - %v with value %v", reflect.TypeOf(v), v)
		}
	}
	return ret, nil
}

func ResolveMx(qname string, config Config) ([]DnsMx, error) {
	var ret []DnsMx
	res, _, err := Resolve(RR_MX, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case DnsMx:
			ret = append(ret, v.(DnsMx))
		default:
			return nil, fmt.Errorf("unknown type - %v with value %v", reflect.TypeOf(v), v)
		}
	}
	return ret, nil
}

func ResolveSrv(qname string, config Config) ([]DnsSRV, error) {
	var ret []DnsSRV
	res, _, err := Resolve(RR_SRV, qname, config)
	if err != nil {
		return nil, err
	}
	for _, v := range res {
		switch v.(type) {
		case DnsSRV:
			ret = append(ret, v.(DnsSRV))
		default:
			return nil, fmt.Errorf("unknown type - %v with value %v", reflect.TypeOf(v), v)
		}
	}
	return ret, nil
}

func ResolveAny(qname string, config Config) ([]interface{}, error) {
	res, _, err := Resolve(RR_ANY, qname, config)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func Resolve(rrtype DnsType, qname string, config Config) ([]interface{}, int, error) {
	return resolve(rrtype, qname, config)
}

func resolve(rrtype DnsType, qname string, config Config) ([]interface{}, int, error) {
	var transactionId int
	var buffer []byte
	var read, written, datasize_int int
	isTCP := config.IsTCP
	proto := "udp"
	if isTCP {
		proto = "tcp"
	}
	conn, err := net.Dial(proto, config.Server)

	if err != nil {
		return nil, transactionId, err
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	q, err := makeQuery(rrtype, qname, 234)
	if err != nil {
		return nil, transactionId, err
	}
	if isTCP { // в tcp надо записать еще и размер данных
		wsize := make([]byte, 2)
		binary.BigEndian.PutUint16(wsize, uint16(len(q)))
		written, err := conn.Write(wsize)
		if err != nil {
			return nil, transactionId, err
		}
		if written != 2 {
			return nil, transactionId, errors.New("wrong read")
		}
	}

	written, err = conn.Write(q)

	if err != nil {
		return nil, transactionId, err
	}
	if written != len(q) {
		return nil, transactionId, errors.New("wrong write")
	}

	if isTCP {
		datasize := make([]byte, 2)
		read, err := conn.Read(datasize)
		if err != nil {
			return nil, transactionId, err
		}
		if read != 2 {
			return nil, transactionId, errors.New("wrong read")
		}
		datasize_int = int(binary.BigEndian.Uint16(datasize))
		buffer = make([]byte, datasize_int, datasize_int)
	} else {
		buffer = make([]byte, 1024)
	}

	if isTCP {
		read, err = io.ReadFull(conn, buffer)
		if err != nil {
			return nil, transactionId, err
		}
		if datasize_int > 0 && read != datasize_int {
			return nil, transactionId, errors.New("wrong read")
		}
	} else {
		read, err = conn.Read(buffer)
		if err != nil {
			return nil, transactionId, err
		}
	}

	return parseDnsAnswer(buffer)
}
