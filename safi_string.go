// generated by stringer --type SAFI,API_TYPE,ROUTE_TYPE,NEXTHOP_FLAG; DO NOT EDIT

package gozebra

import "fmt"

const _SAFI_name = "SAFI_UNICASTSAFI_MULTICASTSAFI_RESERVED_3SAFI_MPLS_VPNSAFI_MAX"

var _SAFI_index = [...]uint8{0, 12, 26, 41, 54, 62}

func (i SAFI) String() string {
	i -= 1
	if i+1 >= SAFI(len(_SAFI_index)) {
		return fmt.Sprintf("SAFI(%d)", i+1)
	}
	return _SAFI_name[_SAFI_index[i]:_SAFI_index[i+1]]
}

const _API_TYPE_name = "INTERFACE_ADDINTERFACE_DELETEINTERFACE_ADDRESS_ADDINTERFACE_ADDRESS_DELETEINTERFACE_UPINTERFACE_DOWNIPV4_ROUTE_ADDIPV4_ROUTE_DELETEIPV6_ROUTE_ADDIPV6_ROUTE_DELETEREDISTRIBUTE_ADDREDISTRIBUTE_DELETEREDISTRIBUTE_DEFAULT_ADDREDISTRIBUTE_DEFAULT_DELETEIPV4_NEXTHOP_LOOKUPIPV6_NEXTHOP_LOOKUPIPV4_IMPORT_LOOKUPIPV6_IMPORT_LOOKUPINTERFACE_RENAMEROUTER_ID_ADDROUTER_ID_DELETEROUTER_ID_UPDATEHELLOMESSAGE_MAX"

var _API_TYPE_index = [...]uint16{0, 13, 29, 50, 74, 86, 100, 114, 131, 145, 162, 178, 197, 221, 248, 267, 286, 304, 322, 338, 351, 367, 383, 388, 399}

func (i API_TYPE) String() string {
	i -= 1
	if i+1 >= API_TYPE(len(_API_TYPE_index)) {
		return fmt.Sprintf("API_TYPE(%d)", i+1)
	}
	return _API_TYPE_name[_API_TYPE_index[i]:_API_TYPE_index[i+1]]
}

const _ROUTE_TYPE_name = "ROUTE_SYSTEMROUTE_KERNELROUTE_CONNECTROUTE_STATICROUTE_RIPROUTE_RIPNGROUTE_OSPFROUTE_OSPF6ROUTE_ISISROUTE_BGPROUTE_HSLSROUTE_OLSRROUTE_BABELROUTE_MAX"

var _ROUTE_TYPE_index = [...]uint8{0, 12, 24, 37, 49, 58, 69, 79, 90, 100, 109, 119, 129, 140, 149}

func (i ROUTE_TYPE) String() string {
	if i+1 >= ROUTE_TYPE(len(_ROUTE_TYPE_index)) {
		return fmt.Sprintf("ROUTE_TYPE(%d)", i)
	}
	return _ROUTE_TYPE_name[_ROUTE_TYPE_index[i]:_ROUTE_TYPE_index[i+1]]
}

const _NEXTHOP_FLAG_name = "NEXTHOP_IFINDEXNEXTHOP_IFNAMENEXTHOP_IPV4NEXTHOP_IPV4_IFINDEXNEXTHOP_IPV4_IFNAMENEXTHOP_IPV6NEXTHOP_IPV6_IFINDEXNEXTHOP_IPV6_IFNAMENEXTHOP_BLACKHOLE"

var _NEXTHOP_FLAG_index = [...]uint8{0, 15, 29, 41, 61, 80, 92, 112, 131, 148}

func (i NEXTHOP_FLAG) String() string {
	i -= 1
	if i+1 >= NEXTHOP_FLAG(len(_NEXTHOP_FLAG_index)) {
		return fmt.Sprintf("NEXTHOP_FLAG(%d)", i+1)
	}
	return _NEXTHOP_FLAG_name[_NEXTHOP_FLAG_index[i]:_NEXTHOP_FLAG_index[i+1]]
}
