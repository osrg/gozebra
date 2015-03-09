// Copyright (C) 2014, 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gozebra

import (
	"encoding/binary"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"net"
)

// Move these somewhere
const (
	AF_INET  = 2
	AF_INET6 = 3
)

const (
	IPV4_MAX_BYTELEN = 4
	IPV6_MAX_BYTELEN = 16
)

const (
	HEADER_SIZE   = 6
	HEADER_MARKER = 255
	VERSION       = 2
)

// Subsequent Address Family Identifier.
type SAFI uint8

const (
	_ SAFI = iota
	SAFI_UNICAST
	SAFI_MULTICAST
	SAFI_RESERVED_3
	SAFI_MPLS_VPN
	SAFI_MAX
)

// API Types.
type API_TYPE uint16

const (
	_ API_TYPE = iota
	INTERFACE_ADD
	INTERFACE_DELETE
	INTERFACE_ADDRESS_ADD
	INTERFACE_ADDRESS_DELETE
	INTERFACE_UP
	INTERFACE_DOWN
	IPV4_ROUTE_ADD
	IPV4_ROUTE_DELETE
	IPV6_ROUTE_ADD
	IPV6_ROUTE_DELETE
	REDISTRIBUTE_ADD
	REDISTRIBUTE_DELETE
	REDISTRIBUTE_DEFAULT_ADD
	REDISTRIBUTE_DEFAULT_DELETE
	IPV4_NEXTHOP_LOOKUP
	IPV6_NEXTHOP_LOOKUP
	IPV4_IMPORT_LOOKUP
	IPV6_IMPORT_LOOKUP
	INTERFACE_RENAME
	ROUTER_ID_ADD
	ROUTER_ID_DELETE
	ROUTER_ID_UPDATE
	HELLO
	MESSAGE_MAX
)

// Route Types.
type ROUTE_TYPE uint8

const (
	ROUTE_SYSTEM ROUTE_TYPE = iota
	ROUTE_KERNEL
	ROUTE_CONNECT
	ROUTE_STATIC
	ROUTE_RIP
	ROUTE_RIPNG
	ROUTE_OSPF
	ROUTE_OSPF6
	ROUTE_ISIS
	ROUTE_BGP
	ROUTE_HSLS
	ROUTE_OLSR
	ROUTE_BABEL
	ROUTE_MAX
)

const (
	MESSAGE_NEXTHOP  = 0x01
	MESSAGE_IFINDEX  = 0x02
	MESSAGE_DISTANCE = 0x04
	MESSAGE_METRIC   = 0x08
)

// Message Flags
type FLAG uint8

const (
	FLAG_INTERNAL  FLAG = 0x01
	FLAG_SELFROUTE FLAG = 0x02
	FLAG_BLACKHOLE FLAG = 0x04
	FLAG_IBGP      FLAG = 0x08
	FLAG_SELECTED  FLAG = 0x10
	FLAG_CHANGED   FLAG = 0x20
	FLAG_STATIC    FLAG = 0x40
	FLAG_REJECT    FLAG = 0x80
)

// Nexthop Flags.
type NEXTHOP_FLAG uint8

const (
	_ NEXTHOP_FLAG = iota
	NEXTHOP_IFINDEX
	NEXTHOP_IFNAME
	NEXTHOP_IPV4
	NEXTHOP_IPV4_IFINDEX
	NEXTHOP_IPV4_IFNAME
	NEXTHOP_IPV6
	NEXTHOP_IPV6_IFINDEX
	NEXTHOP_IPV6_IFNAME
	NEXTHOP_BLACKHOLE
)

type Client struct {
	outgoing      chan *Message
	redistDefault ROUTE_TYPE
	conn          net.Conn
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	for cur := 0; cur < length; {
		if num, err := conn.Read(buf); err != nil {
			return nil, err
		} else {
			cur += num
		}
	}
	return buf, nil
}

func (c *Client) SendCommand(command API_TYPE, body Body) error {
	m := &Message{
		Header: Header{
			Len:     HEADER_SIZE,
			Marker:  HEADER_MARKER,
			Version: VERSION,
			Command: command,
		},
		Body: body,
	}
	c.outgoing <- m
	return nil
}

func (c *Client) SendHello() error {
	if c.redistDefault > 0 {
		body := &HelloBody{
			Redist: c.redistDefault,
		}
		return c.SendCommand(HELLO, body)
	}
	return nil
}

func (c *Client) SendRouterIDAdd() error {
	return c.SendCommand(ROUTER_ID_ADD, nil)
}

func (c *Client) SendInterfaceAdd() error {
	return c.SendCommand(INTERFACE_ADD, nil)
}

func (c *Client) Close() error {
	close(c.outgoing)
	return c.conn.Close()
}

func NewClient(network, address string, typ ROUTE_TYPE) (*Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	outgoing := make(chan *Message)
	go func() {
		for {
			m, more := <-outgoing
			if more {
				b, err := m.Serialize()
				if err != nil {
					log.Warnf("failed to serialize: %s", m)
					continue
				}

				_, err = conn.Write(b)
				if err != nil {
					log.Errorf("failed to write: ", err)
					return
				}
			} else {
				log.Debug("finish outgoing loop")
				return
			}
		}
	}()
	go func() error {
		for {
			headerBuf, err := readAll(conn, HEADER_SIZE)
			if err != nil {
				return err
			}

			hd := &Header{}
			err = hd.DecodeFromBytes(headerBuf)
			if err != nil {
				return err
			}

			bodyBuf, err := readAll(conn, int(hd.Len-HEADER_SIZE))
			if err != nil {
				return err
			}

			m, err := ParseMessage(hd, bodyBuf)
			if err != nil {
				return err
			}
			log.Debugf("recv: %s", m)
		}
	}()
	return &Client{
		outgoing:      outgoing,
		redistDefault: typ,
		conn:          conn,
	}, nil

}

type Header struct {
	Len     uint16
	Marker  uint8
	Version uint8
	Command API_TYPE
}

func (h *Header) Serialize() ([]byte, error) {
	buf := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(buf[0:], h.Len)
	buf[2] = HEADER_MARKER
	buf[3] = VERSION
	binary.BigEndian.PutUint16(buf[4:], uint16(h.Command))
	return buf, nil
}

func (h *Header) DecodeFromBytes(data []byte) error {
	if uint16(len(data)) < HEADER_SIZE {
		return fmt.Errorf("Not all ZAPI message header")
	}
	h.Len = binary.BigEndian.Uint16(data[0:2])
	h.Marker = data[2]
	h.Version = data[3]
	h.Command = API_TYPE(binary.BigEndian.Uint16(data[4:6]))
	return nil
}

type Body interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

type HelloBody struct {
	Redist ROUTE_TYPE
}

func (b *HelloBody) DecodeFromBytes(data []byte) error {
	b.Redist = ROUTE_TYPE(data[0])
	return nil
}

func (b *HelloBody) Serialize() ([]byte, error) {
	return []byte{uint8(b.Redist)}, nil
}

type RouterIDUpdateBody struct {
	Length uint8
	Prefix net.IP
}

func (b *RouterIDUpdateBody) DecodeFromBytes(data []byte) error {
	family := data[0]
	var addrlen int8
	switch family {
	case AF_INET:
		addrlen = IPV4_MAX_BYTELEN
	case AF_INET6:
		addrlen = IPV6_MAX_BYTELEN
	default:
		return fmt.Errorf("unknown address family: %d", family)
	}
	b.Prefix = data[1 : 1+addrlen]
	b.Length = data[1+addrlen]
	return nil
}

func (b *RouterIDUpdateBody) Serialize() ([]byte, error) {
	return []byte{}, nil
}

type IPv4RouteBody struct {
	Type         ROUTE_TYPE
	Flags        FLAG
	Message      uint8
	SAFI         SAFI
	Prefix       net.IP
	PrefixLength uint8
	Nexthops     []net.IP
	Ifindexs     []uint32
	Distance     uint8
	Metric       uint32
}

func (b *IPv4RouteBody) DecodeFromBytes(data []byte) error {
	b.Type = ROUTE_TYPE(data[0])
	b.Flags = FLAG(data[1])
	b.Message = data[2]
	b.SAFI = SAFI(data[3])
	b.Prefix = data[3:7]
	b.PrefixLength = data[7]
	return nil
}

func (b *IPv4RouteBody) Serialize() ([]byte, error) {
	buf := make([]byte, 5)
	buf[0] = uint8(b.Type)
	buf[1] = uint8(b.Flags)
	buf[2] = b.Message
	binary.BigEndian.PutUint16(buf[3:], uint16(b.SAFI))
	ip := b.Prefix.To4()
	if ip == nil {
		return nil, fmt.Errorf("prefix must be IPv4: %s", b.Prefix)
	}
	bitlen := b.PrefixLength
	bytelen := (int(b.PrefixLength) + 7) / 8
	bbuf := make([]byte, bytelen)
	copy(bbuf, ip)
	if bitlen%8 != 0 {
		mask := 0xff00 >> (bitlen % 8)
		last_byte_value := bbuf[bytelen-1] & byte(mask)
		bbuf[bytelen-1] = last_byte_value
	}
	buf = append(buf, bitlen)
	buf = append(buf, bbuf...)

	if b.Message&MESSAGE_NEXTHOP > 0 {
		if b.Flags&FLAG_BLACKHOLE > 0 {
			buf = append(buf, []byte{1, uint8(NEXTHOP_BLACKHOLE)}...)
		} else {
			buf = append(buf, uint8(len(b.Nexthops)+len(b.Ifindexs)))
		}

		for _, v := range b.Nexthops {
			buf = append(buf, uint8(NEXTHOP_IPV4))
			buf = append(buf, v.To4()...)
		}

		for _, v := range b.Ifindexs {
			buf = append(buf, uint8(NEXTHOP_IFINDEX))
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, v)
			buf = append(buf, bbuf...)
		}
	}

	if b.Message&MESSAGE_DISTANCE > 0 {
		buf = append(buf, b.Distance)
	}
	if b.Message&MESSAGE_METRIC > 0 {
		bbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(bbuf, b.Metric)
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

type Message struct {
	Header Header
	Body   Body
}

func (m *Message) Serialize() ([]byte, error) {
	var body []byte
	if m.Body != nil {
		var err error
		body, err = m.Body.Serialize()
		if err != nil {
			return nil, err
		}
	}
	m.Header.Len = uint16(len(body)) + HEADER_SIZE
	hdr, err := m.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func ParseMessage(hdr *Header, data []byte) (*Message, error) {
	m := &Message{Header: *hdr}

	switch m.Header.Command {
	case ROUTER_ID_UPDATE:
		m.Body = &RouterIDUpdateBody{}
	default:
		return nil, fmt.Errorf("Unknown zapi command: %d", m.Header.Command)
	}
	err := m.Body.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return m, nil
}
