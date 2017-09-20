# aix-ipstat
IP traffic statistics (the very little brother of iptraf)
# Example
```
# ./ipstat

   No device specified!


Usage: ./ipstat -d <device>
         [-f "<filter>"] [-i [1..30]] [-p] [-P] [-q] [-s [TPS]] [-u] 
[-c] [-h]

         -c      use colors
         -d      define device, e.g. en0
         -f      pcap/tcpdump filter, e.g. "host foobar and port 22"
         -h      this help
         -i      set refresh interval in seconds (default: 2)
         -n      show hostnames instead of IPs
         -p      show TCP connections with ports
         -P      enable promiscuous mode
         -q      show hostnames with FQDN (implies -n)
         -s      set sort order, [T]ime, [P]ackets, [S]ize (default: T)
         -u      show TCP and UDP connections with ports (implies -p)
```
```
./ipstat -d en0 -P -p

  IPStat
┌ Connections (Host:Port) ──────────────────────────────────────────────── Packets ──────────────── Bytes ─ Flags ┐
│┌xxx.xxx.xxx.xxx:22                                                           453                 20,270   -PA-  │
│└xxx.xxx.xxx.xxx:53925                                                        463                 20,280   --A-  │
│┌xxx.xxx.xxx.xxx:5666                                                          10                  2,439   RESET │
│└xxx.xxx.xxx.xxx:50873                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                          10                  2,439   RESET │
│└xxx.xxx.xxx.xxx:50872                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:41722                                                          4                    474   --A-  │
│└xxx.xxx.xxx.xxx:8194                                                           2                    288   -PA-  │
│┌xxx.xxx.xxx.xxx:5666                                                           9                  2,399   RESET │
│└xxx.xxx.xxx.xxx:47104                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                           9                  2,399   RESET │
│└xxx.xxx.xxx.xxx:47053                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                           9                  2,399   RESET │
│└xxx.xxx.xxx.xxx:50853                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                          10                  2,439   RESET │
│└xxx.xxx.xxx.xxx:50854                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                          10                  2,439   RESET │
│└xxx.xxx.xxx.xxx:46939                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                          10                  2,451   RESET │
│└xxx.xxx.xxx.xxx:46905                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                           9                  2,387   RESET │
│└xxx.xxx.xxx.xxx:50846                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:44271                                                         28                  6,421   --A-  │
│└xxx.xxx.xxx.xxx:636                                                           34                  3,557   -PA-  │
│┌xxx.xxx.xxx.xxx:22                                                             5                    605   -PA-  │
│└xxx.xxx.xxx.xxx:55673                                                          0                      0   ----  │
│┌xxx.xxx.xxx.xxx:5666                                                           8                  2,347   RESET │
│└xxx.xxx.xxx.xxx:46781                                                         0                       0   ----  │
│                                                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Packet Summary ─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ TCP:        2,493 UDP:        5,672 ICMP:        1,496 Other:            0 Dropped:            0                │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Statistics ─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Packets/sec:        4.50       Througput:       298.00 B/s                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

```
# Dependencies for compile
- glib2
- pcap
- ncurses
- gcc
# Tested with following packages (downloaded from perzl.org)
- glib2-2.30.3-2
- glib2-devel-2.30.3-2
- libpcap-1.6.2-1
- libpcap-devel-1.6.2-1
- ncurses-5.9-1
- ncurses-devel-5.9-1
# Compile:
```
gcc ipstat.c `pkg-config --cflags glib-2.0` -Wall -lm -lc -lpcap -lncurses `pkg-config --libs glib-2.0` -o ipstat
```
# Static/Portable compile without later dependencies to pcap, ncurses or glib
```
gcc ipstat.c `pkg-config --cflags glib-2.0` -Wall -Wl,-bstatic -lpcap -liconv -lncurses `pkg-config --libs glib-2.0` -Wl,-bdynamic -lc -lm -lodm -lcfg -lpthread -o ipstat
```
# Notes
- Written and tested on AIX 7.1 TL 3 SP 4
