package dust

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
)

type Event struct {
	PID       uint32
	CPUId     uint32
	Timestamp uint64
	Addr      uint64
	Req       uint64
}

type Flags struct {
	ShowVersion bool
	ShowHelp    bool

	Pid      uint32
	Interval uint32
}

func (f *Flags) SetFlags() {
	flag.BoolVarP(&f.ShowVersion, "version", "v", false, "show version")
	flag.BoolVarP(&f.ShowHelp, "help", "h", false, "show help")
	flag.Uint32VarP(&f.Interval, "interval", "i", 10, "set monitor time in seconds")
	flag.Uint32VarP(&f.Pid, "pid", "p", 0, "filter pid")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [options] \n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}
}

func (f *Flags) PrintHelp() {
	flag.Usage()
}

func (f *Flags) Parse() {
	flag.Parse()
}
