# aix-ipstat

IP traffic statistics (the very little brother of iptraf)

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
