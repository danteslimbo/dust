package dust

type Event struct {
	PID       uint32
	CPUId     uint32
	Timestamp uint64
	Addr      uint64
	Req       uint64
}
