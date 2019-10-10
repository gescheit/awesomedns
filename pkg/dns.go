package awesomedns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"strings"
	"time"
)

type Config struct {
	Server string
}

type DnsSoa struct {
	Name    string
	Mname   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

type DnsRequstedInAnswer struct {
	Name    string
	Type   uint16
	Class  uint16
}

type DnsAnswerHeader struct {
	Name    string
	Type   dns_type
	Class  uint16
	Ttl  uint32
}

type DnsMx struct {
	Preference uint16
	Exchange   string
}
type DnsSRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}
type DnsMessageHeader struct {
	ID      uint16
	Query   bool
	Opcode  uint8 // 4 bits
	AA      bool  // Authoritative Answer
	TC      bool  // Truncation Flag
	RD      bool  // Recursion Desired:
	RA      bool  // Recursion Available
	Z       bool  // Zero: One reserved bits set to zero
	AC      bool
	CD      bool
	RCode   uint8  // Response code
	QDCount uint16 // Question Count
	ANCount uint16 // Answer Record Count
	NSCount uint16 // Authority Record Count
	ARCount uint16 // Additional Record Count
}

const headerLen = 12

type dns_type = int

const (
	RR_A     dns_type = 1
	RR_NS    dns_type = 2
	RR_AAAA  dns_type = 28
	RR_CNAME dns_type = 5
	RR_SOA   dns_type = 6
	RR_PTR   dns_type = 12
	RR_MX    dns_type = 15
	RR_SRV   dns_type = 33
	RR_ANY   dns_type = 255
)

const MaxLabelLen = 163
const MaxNameLen = 255

func ResolveA(qname string, config Config) ([]net.IP, error) {
	var ret []net.IP
	res, err := Resolve(RR_A, qname, config)
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

func ResolveAaaa(qname string, config Config) ([]net.IP, error) {
	var ret []net.IP
	res, err := Resolve(RR_AAAA, qname, config)
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
	res, err := Resolve(RR_CNAME, qname, config)
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
	res, err := Resolve(RR_NS, qname, config)
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
	res, err := Resolve(RR_SOA, qname, config)
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
	res, err := Resolve(RR_PTR, qname, config)
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
	res, err := Resolve(RR_MX, qname, config)
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
	res, err := Resolve(RR_SRV, qname, config)
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
	res, err := Resolve(RR_ANY, qname, config)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func Resolve(rrtype dns_type, qname string, config Config) ([]interface{}, error) {
	var ret []interface{}
	var n int
	conn, err := net.Dial("udp", config.Server)

	if err != nil {
		return nil, err
	}
	defer conn.Close()
	q, err := makeQuery(rrtype, qname)
	if err != nil {
		return nil, err
	}
	log.Printf("%v makeQuery", q)
	if n, err = conn.Write(q); err != nil {
		return nil, err
	}
	log.Printf("%v bytes written", n)

	// receive message from server
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err = conn.Read(buffer); err != nil {
		return nil, err
	}
	log.Printf("%v bytes read", n)
	ans, err := parseDnsHeader(buffer)
	if err != nil {
		return nil, err
	}
	if ans.RCode > 0 {
		switch ans.RCode {
		case 1:
			return nil, errors.New("Format error")
		case 2:
			return nil, errors.New("Server failure")
		case 3:
			return nil, errors.New("Name Error")
		case 4:
			return nil, errors.New("Not Implemented")
		case 5:
			return nil, errors.New("Refused")
		default:
			return nil, errors.New("wrong code")
		}
	}
	var namesCache = map[int]string{}
	var position int = 12 // header
	if ans.QDCount != 1 {
		// кажется нигде не описано а никто не поодерживает больше одного запроса
		return nil, fmt.Errorf("unsupported question number %v", ans.QDCount)
	}
	for i := 0; i < int(ans.QDCount); i++ {
		// парсим запрос так как на него могут ссылаться в ответе
		answerQuestion, err := parseDnsQuestionSection(buffer, &position, namesCache)
		log.Println("answer question:", answerQuestion)
		if err != nil {
			return nil, err
		}
	}
	for i := 0; i < int(ans.ANCount); i++ {
		answer, header, err := parseDnsAnswerSection(buffer, &position, namesCache)
		if err != nil {
			return nil, err
		}
		ret = append(ret, answer)
		fmt.Println("answer section:", header, answer)
	}
	return ret, nil
}

// subset has to go from lowest to highest
func bits(b uint, subset ...uint) (r uint) {
	i := uint(0)
	for _, v := range subset {
		if b&(1<<v) > 0 {
			r = r | 1<<uint(i)
		}
		i++
	}
	return
}

func makeQuery(rrtype dns_type, qname string) ([]byte, error) {
	res := make([]byte, 400)
	var header = DnsMessageHeader{}

	header.ID = 123
	header.RD = true
	header.QDCount = 1

	binary.BigEndian.PutUint16(res[0:], header.ID)
	if header.Query {
		res[2] = 0b1000_0000
	}
	if header.Opcode > 0 {
		res[2] |= header.Opcode << 3
	}
	if header.AA {
		res[2] |= 0b100
	}
	if header.TC {
		res[2] |= 0b10
	}
	if header.RD {
		res[2] |= 0b1
	}
	if header.RA {
		res[3] |= 0b1000_0000
	}
	if header.Z {
		res[3] |= 0b100_0000
	}
	if header.AC {
		res[3] |= 0b10_0000
	}
	if header.CD {
		res[3] |= 0b1_0000
	}
	if header.RCode > 0 {
		res[3] |= header.RCode
	}
	if header.QDCount > 0 {
		binary.BigEndian.PutUint16(res[4:], header.QDCount)
	}
	if header.ANCount > 0 {
		binary.BigEndian.PutUint16(res[6:], header.ANCount)
	}
	if header.NSCount > 0 {
		binary.BigEndian.PutUint16(res[8:], header.NSCount)
	}
	if header.ARCount > 0 {
		binary.BigEndian.PutUint16(res[10:], header.ARCount)
	}

	n, err := buildDnsQuestionSection(rrtype, res[12:], qname)
	if err != nil {
		return nil, err
	}
	return res[0 : 12+n], nil
}

func readName(data []byte, nameCache map[int]string, packetPos int) (string, int, error) {
	// декодирование строки
	// кодируется как байт с длинной n и последующие n байт имени
	var labels []string
	var label string
	current_offset := 0
	for {
		namePartLen := int(data[current_offset])
		if namePartLen > MaxLabelLen {
			// rfc1035 4.1.4 компрессия
			if namePartLen&0b1100_0000 != 0b1100_0000 {
				panic("wrong compression mask")
			}
			// cтаршие 2 бита это флаг компрессии, а оставшиеся - смещение от начала пакета
			offset := binary.BigEndian.Uint16(data[current_offset:current_offset+2]) << 2 >> 2
			if offset < headerLen {
				return "", current_offset, fmt.Errorf("offset is too small %v", offset)
			}
			nameFromCache, ok := nameCache[int(offset)]
			if ! ok {
				return "", current_offset, fmt.Errorf("unable to find name with offset %v", int(offset))
			}
			labels = append(labels, nameFromCache)
			current_offset += 2
			break
		} else {
			current_offset++
			if namePartLen == 0 {
				break
			}
			label = string(data[current_offset : namePartLen+current_offset])
			labels = append(labels, label)
			current_offset += namePartLen
		}
	}
	label_index := 0
	for i, label := range labels {
		nameCache[label_index+packetPos] = strings.Join(labels[i:], ".")
		label_index += len(label)
		label_index++
	}
	return strings.Join(labels, "."), current_offset, nil
}
func encodeName(s string) ([]byte, error) {
	res := make([]byte, MaxNameLen)
	var pos int = 0
	for _, element := range strings.Split(s, ".") {
		if len(element) > MaxLabelLen {
			return nil, fmt.Errorf("name %v is too long %v > %v", element, len(element), MaxLabelLen)
		}
		res[pos] = byte(len(element))
		pos++
		copy(res[pos:], element)
		pos += len(element)
		if pos+1 > MaxNameLen {
			return nil, errors.New("too long name to encode")
		}
	}
	res[pos] = 0
	pos++
	return res[0:pos], nil
}

func parseDnsQuestionSection(data []byte, position *int, nameCache map[int]string) (DnsRequstedInAnswer, error) {
	var pos = *position
	var res DnsRequstedInAnswer
	name, read, _ := readName(data[pos:], nameCache, pos)
	pos += read

	typ := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	class := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	res.Class = class
	res.Type = typ
	res.Name = name
	*position = pos
	return res, nil
}

func buildDnsQuestionSection(rrtype dns_type, data []byte, qname string) (int, error) {
	var err error
	name, err := encodeName(qname)
	if err != nil {
		return 0, err
	}
	copy(data, name)
	pos := len(name)
	binary.BigEndian.PutUint16(data[pos:], uint16(rrtype))
	pos += 2
	binary.BigEndian.PutUint16(data[pos:], 1)
	pos += 2
	return pos, nil
}

func parseDnsAnswerSection(data []byte, position *int, nameCache map[int]string) (interface{}, DnsAnswerHeader, error) {
	var pos = *position
	var ret interface{}
	var header DnsAnswerHeader
	name, read, err := readName(data[pos:], nameCache, pos)
	if err != nil {
		return nil,header, err
	}
	pos += read

	typ := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	class := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	ttl := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	dataLen := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	rdata := data[pos : pos+int(dataLen)]
	switch dns_type(typ) {
	case RR_A:
		if dataLen != 4 {
			return nil, header, fmt.Errorf("wrong data size for A type - %v", dataLen)
		}
		ret = net.IP(rdata)
	case RR_AAAA:
		if dataLen != 16 {
			return nil, header, fmt.Errorf("wrong data size for AAAA type - %v", dataLen)
		}
		ret = net.IP(rdata)
	case RR_CNAME, RR_NS, RR_PTR:
		ret, _, err = readName(rdata, nameCache, pos)
		if err != nil {
			return nil, header, err
		}
	case RR_SOA:
		soa_name, read, err := readName(rdata, nameCache, pos)
		if err != nil {
			return nil, header, err
		}
		soa_rname, _, err := readName(rdata[read:], nameCache, pos)
		if err != nil {
			return nil, header, err
		}
		serial := binary.BigEndian.Uint32(rdata)
		refresh := binary.BigEndian.Uint32(rdata[4:])
		retry := binary.BigEndian.Uint32(rdata[8:])
		expire := binary.BigEndian.Uint32(rdata[12:])
		minimum := binary.BigEndian.Uint32(rdata[16:])
		ret = DnsSoa{soa_name, soa_rname, serial, refresh, retry, expire, minimum}
	case RR_MX:
		preference := binary.BigEndian.Uint16(rdata)
		exchange, _, err := readName(rdata[2:], nameCache, pos)
		if err != nil {
			return nil, header,err
		}
		ret = DnsMx{preference, exchange}
	case RR_SRV:
		priority := binary.BigEndian.Uint16(rdata)
		weight := binary.BigEndian.Uint16(rdata[2:])
		port := binary.BigEndian.Uint16(rdata[4:])
		target, _, err := readName(rdata[6:], nameCache, pos)
		if err != nil {
			return nil,header, err
		}
		ret = DnsSRV{priority, weight, port, target}
	default:
		return nil, header,fmt.Errorf("unsupported data type %v", typ)
	}
	header = DnsAnswerHeader{name, dns_type(typ),class, ttl}
	pos += int(dataLen)
	*position = pos
	return ret, header, nil
}

func parseDnsHeader(data []byte) (DnsMessageHeader, error) {
	var res DnsMessageHeader
	if len(data) < 12 {
		return res, errors.New("too few bytes to encode")
	}
	res.ID = binary.BigEndian.Uint16(data[0:2])
	tmp := uint8(data[2])
	res.Query = tmp&0b1000_0000 == 0
	res.Opcode = tmp & 0b111_1000
	res.AA = tmp&0b100 == 1
	res.TC = tmp&0b10 == 1
	res.RD = tmp&0b1 == 1
	tmp = data[3]
	res.RA = tmp&0b1000_0000 == 1
	res.Z = tmp&0b100_0000 == 1
	res.AC = tmp&0b10_0000 == 1
	res.CD = tmp&0b1_0000 == 1
	res.RCode = tmp & 0b1111
	res.QDCount = binary.BigEndian.Uint16(data[4:6])
	res.ANCount = binary.BigEndian.Uint16(data[6:8])
	res.NSCount = binary.BigEndian.Uint16(data[8:10])
	res.ARCount = binary.BigEndian.Uint16(data[10:12])
	return res, nil
}

func (msg DnsMessageHeader) String() string {
	if msg.Query {
		return fmt.Sprintf("Query ID=%v QDCount=%v ANCount=%v", msg.ID, msg.QDCount, msg.ANCount)
	} else {
		return fmt.Sprintf("Answer ID=%v QDCount=%v ANCount=%v", msg.ID, msg.QDCount, msg.ANCount)
	}
}
