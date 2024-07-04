# dust
`dust` is a [pwru](https://github.com/cilium/pwru) to trace io request
## Why dust?
As we all know, io requests initiated by processes go through a long process before they finally hit the disk, during which the io request is handled by the kworker. This asynchronous processing makes it very difficult to track io, so we start with the io request and track the io request's lifecycle.

`dust` tracks the io request returned by `blk_mq_alloc_request` and monitors how long it runs in all functions that call `struct request *`, giving a clearer picture of the io request lifecycle.
## TL;DR
Usage:

```shell
./dust -h
Usage: ./dust [options]
    Available options:
  -h, --help              show help
  -i, --interval uint32   set monitor time in seconds (default 10)
  -o, --ofile string      output file
  -p, --pid uint32        filter pid
  -v, --version           show version
```
Example: trace a process for 30 seconds.
```shell
sudo ./dust -p {the_process_you_want_to_trace} -i 30
```

## TODO
- [ ] kprobe filters.
- [ ] kprobe.multi supports.
- [x] output to files.