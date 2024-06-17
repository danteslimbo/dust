package dust

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/TwiN/go-color"
	"github.com/tklauser/ps"
)

const absoluteTS string = "15:04:05.000"

type output struct {
	addr2name    Addr2Name
	writer       *os.File
	kprobeMulti  bool // TODO
	kfreeReasons map[uint64]string
	ifaceCache   map[uint64]map[uint32]string
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

func NewOutput(addr2Name Addr2Name, kprobeMulti bool) (*output, error) {
	writer := os.Stdout

	var ifs map[uint64]map[uint32]string

	return &output{
		addr2name:    addr2Name,
		writer:       writer,
		kprobeMulti:  kprobeMulti,
		kfreeReasons: nil,
		ifaceCache:   ifs,
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

func (o *output) Print(event *Event) {
	_, _ = fmt.Fprintf(o.writer, "%12s ", getAbsoluteTs())

	execName := getExecName(int(event.PID))
	addr := getAddrByArch(event, o)
	funcName := getOutFuncName(o, addr)

	line := color.Colorize(chooseColor(event.Req), fmt.Sprintf(
		"%d,  0x%x, %d, %16s, %24s",
		event.Timestamp,
		event.Req,
		event.PID,
		fmt.Sprintf("[%s]", execName), funcName))
	_, _ = fmt.Fprintln(o.writer, line)
}

func (o *output) getIfaceName(netnsInode, ifindex uint32) string {
	if ifaces, ok := o.ifaceCache[uint64(netnsInode)]; ok {
		if name, ok := ifaces[ifindex]; ok {
			return fmt.Sprintf("%d(%s)", ifindex, name)
		}
	}
	return fmt.Sprintf("%d", ifindex)
}

func getOutFuncName(o *output, addr uint64) string {
	var funcName string
	if ksym, ok := o.addr2name.Addr2NameMap[addr]; ok {
		funcName = ksym.name
	} else if ksym, ok := o.addr2name.Addr2NameMap[addr-4]; runtime.GOARCH == "amd64" && ok {
		// Assume that function has ENDBR in its prelude (enabled by CONFIG_X86_KERNEL_IBT).
		// See https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
		// for more ctx.
		funcName = ksym.name
	} else {
		funcName = fmt.Sprintf("0x%x", addr)
	}

	return funcName
}

var colors = []string{
	color.Black,
	color.Red,
	color.Green,
	color.Yellow,
	color.Blue,
	color.Purple,
	color.Cyan,
	color.Gray,
	color.White,
}

var numColors = uint64(len(colors))

func chooseColor(req uint64) string {
	return colors[int(req%numColors)]
}
