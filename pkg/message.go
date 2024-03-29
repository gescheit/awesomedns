// подробности rfc1035
// формат сообщений:
// +---------------------+
// |        Header       | обязательный заголовок в 12 байт. тут есть код ошибки, количество секций question, answer...
// +---------------------+
// |       Question      | запрос, в том числе будет в ответе
// +---------------------+
// |        Answer       | ответ. может быть несколько в том числе разного типа
// +---------------------+
// |      Authority      | RRs pointing toward an authority - не реализовано
// +---------------------+
// |      Additional     | RRs holding additional information - не реализовано
// +---------------------+

package awesomedns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
)

type Config struct {
	Server string
	IsTCP  bool
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

type DnsLoc struct {
	Version uint8
	Size    uint8
}

type DnsNaptr struct {
	Order       uint16
	Preference  uint16
	Flag        string
	Service     string
	Regex       string
	Replacement string
}

type DnsRp struct {
	Mailbox string
	TXTRR   string
}

type DnsRequestedInAnswer struct {
	Name  string
	Type  DnsType
	Class class
}

type DnsAnswerHeader struct {
	Name  string
	Type  DnsType
	Class class
	Ttl   uint32
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

type DnsType = int

const (
	RR_A     DnsType = 1
	RR_NS    DnsType = 2
	RR_AAAA  DnsType = 28
	RR_CNAME DnsType = 5
	RR_SOA   DnsType = 6
	RR_PTR   DnsType = 12
	RR_HINFO DnsType = 13
	RR_MX    DnsType = 15
	RR_TXT   DnsType = 16
	RR_RP    DnsType = 17 // rfc1183
	RR_AFSDB DnsType = 18 // rfc5864
	RR_LOC   DnsType = 29 // rfc1876
	RR_SRV   DnsType = 33
	RR_NAPTR DnsType = 35 // rfc2915
	RR_AXFR  DnsType = 252
	RR_ANY   DnsType = 255
)

var RRnames = map[DnsType]string{
	RR_A:     "A",
	RR_NS:    "NS",
	RR_AAAA:  "AAAA",
	RR_CNAME: "CNAME",
	RR_SOA:   "SOA",
	RR_PTR:   "PTR",
	RR_HINFO: "HINFO",
	RR_MX:    "MX",
	RR_RP:    "RP",
	RR_TXT:   "TXT",
	RR_AFSDB: "AFSDB",
	RR_LOC:   "LOC",
	RR_SRV:   "SRV",
	RR_NAPTR: "NAPTR",
	RR_AXFR:  "RR_AXFR",
	RR_ANY:   "ANY",
}

type class = int

const (
	ClassIN class = 1
)

var ClassNames = map[DnsType]string{
	ClassIN: "IN",
}

const MaxLabelLen = 163
const MaxNameLen = 255

var (
	errFormat         = errors.New("format error")
	errServFail       = errors.New("server failure")
	errNameError      = errors.New("name Error")
	errNotImplemented = errors.New("not Implemented")
	errRefused        = errors.New("refused")

	errCompressionMask = errors.New("wrong compression mask")
)

func parseDnsAnswer(data []byte) ([]interface{}, int, error) {
	var transactionId int
	var ret []interface{}
	ans, err := parseDnsHeader(data)
	if err != nil {
		return nil, transactionId, err
	}
	transactionId = int(ans.ID)
	if ans.RCode > 0 {
		switch ans.RCode {
		case 1:
			err = errFormat
		case 2:
			err = errServFail
		case 3:
			err = errNameError
		case 4:
			err = errNotImplemented
		case 5:
			err = errRefused
		default:
			err = fmt.Errorf("unknown answer error %v", ans.RCode)
		}
		return nil, transactionId, err
	}
	var namesCache = map[int]string{}
	var position int = 12 // длина заголовка
	if ans.QDCount != 1 {
		// кажется нигде не описано и никто не поддерживает больше одного запроса
		return nil, transactionId, fmt.Errorf("unsupported question number %v", ans.QDCount)
	}
	for i := 0; i < int(ans.QDCount); i++ {
		// парсим запрос так как на него могут ссылаться в ответе
		answerQuestion, err := parseDnsQuestionSection(data, &position, namesCache)
		log.Println("answer question:", answerQuestion)
		if err != nil {
			return nil, transactionId, err
		}
	}
	for i := 0; i < int(ans.ANCount); i++ {
		answer, header, err := parseDnsAnswerSection(data, &position, namesCache)
		if err != nil {
			return nil, transactionId, err
		}
		ret = append(ret, answer)
		log.Println("answer section:", header, answer)
	}
	return ret, transactionId, nil
}

func makeQuery(rrtype DnsType, qname string, requestId int) ([]byte, error) {
	res := make([]byte, 400)
	var header = DnsMessageHeader{}

	header.ID = uint16(requestId)
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
	var name string
	currentOffset := 0
	for {
		namePartLen := int(data[currentOffset])
		if namePartLen > MaxLabelLen {
			// rfc1035 4.1.4 компрессия
			if namePartLen&0b1100_0000 != 0b1100_0000 {
				return name, currentOffset, errCompressionMask
			}
			// cтаршие 2 бита это флаг компрессии, а оставшиеся - смещение от начала пакета
			offset := binary.BigEndian.Uint16(data[currentOffset:currentOffset+2]) << 2 >> 2
			if offset < headerLen {
				return name, currentOffset, fmt.Errorf("offset is too small %v", offset)
			}
			nameFromCache, ok := nameCache[int(offset)]
			if !ok {
				return name, currentOffset, fmt.Errorf("unable to find name with offset %v", int(offset))
			}
			labels = append(labels, nameFromCache)
			currentOffset += 2
			break
		} else {
			currentOffset++
			if namePartLen == 0 {
				break
			}
			label = string(data[currentOffset : namePartLen+currentOffset])
			labels = append(labels, label)
			currentOffset += namePartLen
		}
	}
	labelIndex := 0
	for i, label := range labels {
		nameCache[labelIndex+packetPos] = strings.Join(labels[i:], ".")
		labelIndex += len(label)
		labelIndex++
	}
	return strings.Join(labels, "."), currentOffset, nil
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

func parseDnsQuestionSection(data []byte, position *int, nameCache map[int]string) (DnsRequestedInAnswer, error) {
	var pos = *position
	var res DnsRequestedInAnswer
	name, read, _ := readName(data[pos:], nameCache, pos)
	pos += read

	typ := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	klass := binary.BigEndian.Uint16(data[pos : pos+2])
	if class(klass) != ClassIN {
		return res, fmt.Errorf("unsupported class %v", klass)
	}
	pos += 2
	res.Class = class(klass)
	res.Type = DnsType(typ)
	res.Name = name
	*position = pos
	return res, nil
}

func buildDnsQuestionSection(rrtype DnsType, data []byte, qname string) (int, error) {
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
		return nil, header, err
	}
	pos += read

	typ := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	klass := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	ttl := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	rdlength := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	rdata := make([]byte, rdlength)
	copy(rdata, data[pos:pos+int(rdlength)])
	switch DnsType(typ) {
	case RR_A:
		if rdlength != 4 {
			return nil, header, fmt.Errorf("wrong data size for A type - %v", rdlength)
		}
		ret = net.IP(rdata)
	case RR_AAAA:
		if rdlength != 16 {
			return nil, header, fmt.Errorf("wrong data size for AAAA type - %v", rdlength)
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
		soa_rname, _, err := readName(rdata[read:], nameCache, pos+read)
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
		exchange, _, err := readName(rdata[2:], nameCache, pos+2)
		if err != nil {
			return nil, header, err
		}
		ret = DnsMx{preference, exchange}
	case RR_SRV:
		priority := binary.BigEndian.Uint16(rdata)
		weight := binary.BigEndian.Uint16(rdata[2:])
		port := binary.BigEndian.Uint16(rdata[4:])
		target, _, err := readName(rdata[6:], nameCache, pos+6)
		if err != nil {
			return nil, header, err
		}
		ret = DnsSRV{priority, weight, port, target}
	case RR_HINFO:
		cpuLength := rdata[0]
		cpu := string(rdata[1 : int(cpuLength)+1])
		ret = cpu
	case RR_TXT:
		txtLength := rdata[0]
		txt := string(rdata[1 : int(txtLength)+1])
		ret = txt
	case RR_AFSDB:
		//subtype := binary.BigEndian.Uint16(rdata)
		hostname, _, err := readName(rdata[2:], nameCache, pos+2)
		if err != nil {
			return nil, header, err
		}
		ret = hostname
	case RR_LOC:
		version := rdata[0]
		size := rdata[1]
		// TODO: декодировать остальные поля
		ret = DnsLoc{version, size}
	case RR_NAPTR:
		order := binary.BigEndian.Uint16(rdata)
		pref := binary.BigEndian.Uint16(rdata[2:])
		flag_length := rdata[4]
		rdataPos := 5
		flag := string(rdata[rdataPos : rdataPos+int(flag_length)])
		rdataPos += int(flag_length)
		service_length := rdata[rdataPos]
		rdataPos++
		service := string(rdata[rdataPos : rdataPos+int(service_length)])
		rdataPos += int(service_length)
		regexLength := rdata[rdataPos]
		rdataPos++
		regex := string(rdata[rdataPos : rdataPos+int(regexLength)])
		rdataPos += int(regexLength)
		replacement, _, err := readName(rdata[rdataPos:], nameCache, pos+rdataPos)
		if err != nil {
			return nil, header, err
		}
		ret = DnsNaptr{order, pref, flag, service, regex, replacement}
	case RR_RP:
		mailbox, read, err := readName(rdata, nameCache, pos)
		if err != nil {
			return nil, header, err
		}
		txtRR, read, err := readName(rdata[read:], nameCache, pos+read)
		if err != nil {
			return nil, header, err
		}
		ret = DnsRp{mailbox, txtRR}
	default:
		return nil, header, fmt.Errorf("unsupported data type %v", typ)
	}
	header = DnsAnswerHeader{name, DnsType(typ), class(klass), ttl}
	pos += int(rdlength)
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

func (msg DnsRequestedInAnswer) String() string {
	return fmt.Sprintf("requested{name:%v, class:%v, type:%v}", msg.Name, ClassNames[msg.Class], RRnames[msg.Type])
}

func (msg DnsAnswerHeader) String() string {
	return fmt.Sprintf("answer header{name:%v, class:%v, type:%v, ttl:%v}", msg.Name, ClassNames[msg.Class], RRnames[msg.Type], msg.Ttl)
}
