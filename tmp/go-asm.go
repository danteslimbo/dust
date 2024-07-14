package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const bpfFCurrentCPU = 0xffffffff

var progSpec = &ebpf.ProgramSpec{
	Name:    "my_program",
	Type:    ebpf.TracePoint,
	License: "GPL",
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("setting temporary rlimit: %s", err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "pids_map",
	})
	if err != nil {
		log.Fatalf("creating perf event array: %s", err)
	}

	defer events.Close()

	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		rd.Close()
	}()

	progSpec.Instructions = asm.Instructions{
		// r6 = r1
		asm.Mov.Reg(asm.R6, asm.R1),

		// r1 = *(u64 *)(r6 + 16)
		asm.LoadMem(asm.R1, asm.R6, 16, asm.DWord),

		// if r1 != 0 goto +11 <LBB0_2>
		asm.JNE.Imm(asm.R1, 0, "exit"),

		// call 14
		// *(u64 *)(r10 - 8) = r0
		asm.FnGetCurrentPidTgid.Call(),

		// r0 >>= 32
		asm.RSh.Imm(asm.R0, 32),

		// *(u64 *)(r10 - 8) = r0
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),

		// r4 = r10
		asm.Mov.Reg(asm.R4, asm.RFP),

		// r4 += -8
		asm.Add.Imm(asm.R4, -8),

		// r1 = r6
		asm.Mov.Reg(asm.R1, asm.R6),

		// r2 = 0 ll
		asm.LoadMapPtr(asm.R2, events.FD()),

		// r3 = 4294967295 ll
		asm.LoadImm(asm.R3, bpfFCurrentCPU, asm.DWord),

		// r5  = 8
		asm.Mov.Imm(asm.R5, 8),

		// call 25
		asm.FnPerfEventOutput.Call(),

		// r0 = 0
		asm.Mov.Imm(asm.R0, 0).Sym("exit"),

		// exit
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}
	defer prog.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_read", prog)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Fatalf("reading from reader: %s", err)
		}

		data := binary.LittleEndian.Uint64(record.RawSample)
		fmt.Println(data)
	}
}
