package awesomedns

import (
	"errors"
	"fmt"
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
	conn, err := net.Dial("udp", config.Server)

	if err != nil {
		return nil, transactionId, err
	}

	q, err := makeQuery(rrtype, qname, 234)
	if err != nil {
		return nil, transactionId, err
	}
	if n, err = conn.Write(q); err != nil {
		return nil, transactionId, err
	}
	// receive message from server
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err = conn.Read(buffer); err != nil {
		return nil, transactionId, err
	}
	return parseDnsAnswer(buffer)
}
