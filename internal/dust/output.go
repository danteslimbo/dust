package dust

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/tklauser/ps"
)

const absoluteTS string = "15:04:05.000"

type output struct {
	lastSeenSkb    map[uint64]uint64 // skb addr => last seen TS
	printSkbMap    *ebpf.Map
	printShinfoMap *ebpf.Map
	printStackMap  *ebpf.Map
	addr2name      Addr2Name
	writer         *os.File
	kprobeMulti    bool
	kfreeReasons   map[uint64]string
	ifaceCache     map[uint64]map[uint32]string
}

// outputStructured is a struct to hold the data for the json output
type jsonPrinter struct {
	Skb         string      `json:"skb,omitempty"`
	Shinfo      string      `json:"skb_shared_info,omitempty"`
	Process     string      `json:"process,omitempty"`
	Func        string      `json:"func,omitempty"`
	Time        interface{} `json:"time,omitempty"`
	Netns       uint32      `json:"netns,omitempty"`
	Mark        uint32      `json:"mark,omitempty"`
	Iface       string      `json:"iface,omitempty"`
	Proto       uint16      `json:"proto,omitempty"`
	Mtu         uint32      `json:"mtu,omitempty"`
	Len         uint32      `json:"len,omitempty"`
	Tuple       *jsonTuple  `json:"tuple,omitempty"`
	Stack       interface{} `json:"stack,omitempty"`
	SkbMetadata interface{} `json:"skb_metadata,omitempty"`
}

type jsonTuple struct {
	Saddr string `json:"saddr,omitempty"`
	Daddr string `json:"daddr,omitempty"`
	Sport uint16 `json:"sport,omitempty"`
	Dport uint16 `json:"dport,omitempty"`
	Proto uint8  `json:"proto,omitempty"`
}

func NewOutput(printSkbMap, printShinfoMap, printStackMap *ebpf.Map, addr2Name Addr2Name, kprobeMulti bool, btfSpec *btf.Spec) (*output, error) {
	writer := os.Stdout

	//reasons, err := getKFreeSKBReasons(btfSpec)
	//if err != nil {
	//	log.Printf("Unable to load packet drop reaons: %v", err)
	//}

	var ifs map[uint64]map[uint32]string

	return &output{
		lastSeenSkb:    map[uint64]uint64{},
		printSkbMap:    printSkbMap,
		printShinfoMap: printShinfoMap,
		printStackMap:  printStackMap,
		addr2name:      addr2Name,
		writer:         writer,
		kprobeMulti:    kprobeMulti,
		kfreeReasons:   nil,
		ifaceCache:     ifs,
	}, nil
}

func (o *output) Close() {
	if o.writer != os.Stdout {
		_ = o.writer.Sync()
		_ = o.writer.Close()
	}
}

func (o *output) PrintHeader() {
	// TODO

}

// PrintJson prints the event in JSON format
func (o *output) PrintJson(event *Event) {
	// crate an instance of the outputStructured struct to hold the data
	d := &jsonPrinter{}

	// add the data to the struct
	d.Process = getExecName(int(event.PID))
	//d.Func = getOutFuncName(o, event, event.Addr)

	// Create new encoder to write the json to stdout or file depending on the flags
	encoder := json.NewEncoder(o.writer)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(d)

	if err != nil {
		log.Fatalf("Error encoding JSON: %s", err)
	}
}

func getAbsoluteTs() string {
	return time.Now().Format(absoluteTS)
}

func getRelativeTs(event *Event, o *output) uint64 {
	return 0 // TODO
}

func getExecName(pid int) string {
	p, err := ps.FindProcess(pid)
	execName := fmt.Sprintf("<empty>:(%d)", pid)
	if err == nil && p != nil {
		return fmt.Sprintf("%s:%d", p.ExecutablePath(), pid)
	}
	return execName
}

func getAddrByArch(event *Event, o *output) (addr uint64) {
	switch runtime.GOARCH {
	case "amd64":
		addr = event.Addr
		if !o.kprobeMulti {
			addr -= 1
		}
	case "arm64":
		addr = event.Addr
	}
	return addr
}

func getTupleData(event *Event) (tupleData string) {
	return "" // TODO
}

func getStackData(event *Event, o *output) (stackData string) {
	return // TODO
}

func (o *output) Print(event *Event) {

	_, _ = fmt.Fprintf(o.writer, "%12s ", getAbsoluteTs())

	execName := getExecName(int(event.PID))

	fmt.Fprintf(o.writer, "0x%x,%16s %24s",
		event.Req,
		fmt.Sprintf("[%s]", execName), "")

	fmt.Fprintln(o.writer)
}

func (o *output) getIfaceName(netnsInode, ifindex uint32) string {
	if ifaces, ok := o.ifaceCache[uint64(netnsInode)]; ok {
		if name, ok := ifaces[ifindex]; ok {
			return fmt.Sprintf("%d(%s)", ifindex, name)
		}
	}
	return fmt.Sprintf("%d", ifindex)
}

func protoToStr(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	case syscall.IPPROTO_ICMPV6:
		return "icmp6"
	default:
		return ""
	}
}

func addrToStr(proto uint16, addr [16]byte) string {
	switch proto {
	case syscall.ETH_P_IP:
		return net.IP(addr[:4]).String()
	case syscall.ETH_P_IPV6:
		return fmt.Sprintf("[%s]", net.IP(addr[:]).String())
	default:
		return ""
	}
}
