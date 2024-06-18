package dust

var Version = "version unknown"

type DustCfg struct {
	Pid uint32
}

func GetConfig(flag *Flags) DustCfg {
	return DustCfg{Pid: flag.Pid}
}
