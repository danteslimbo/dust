package dust

type Event struct {
	PID       uint32
	Type      uint32
	Addr      uint64
	Timestamp uint64
	Req       uint64
}
