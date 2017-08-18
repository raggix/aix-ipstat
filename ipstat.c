/*
#==============================================================================
# Program       : ipstat
#
# Description   : IP traffic statistics (the very little brother of iptraf)
#
# Author        : Ron Wellnitz
#
# Version       : 1.0
#
#------------------------------------------------------------------------------
# History:
#
# <DATE>        <AUTHOR>        <REASON>
# ----------    -------------- -----------------------------------------------
# 2015-11-11    Ron Wellnitz    initial creation
#
#------------------------------------------------------------------------------
# Dependencies for compile:
#   - glib2
#   - pcap
#   - ncurses
#   - gcc
#
# Tested with following packages (downloaded from perzl.org):
#   - glib2-2.30.3-2
#   - glib2-devel-2.30.3-2
#   - libpcap-1.6.2-1
#   - libpcap-devel-1.6.2-1
#   - ncurses-5.9-1
#   - ncurses-devel-5.9-1
#
#------------------------------------------------------------------------------
# Compile:
#   gcc ipstat.c `pkg-config --cflags glib-2.0` -Wall -lm -lc -lpcap \
#     -lncurses `pkg-config --libs glib-2.0` -o ipstat
#
# Static/Portable compile without later dependencies to pcap, ncurses or glib:
#   gcc ipstat.c `pkg-config --cflags glib-2.0` -Wall -Wl,-bstatic -lpcap \
#     -liconv -lncurses `pkg-config --libs glib-2.0` -Wl,-bdynamic -lc -lm \
#     -lodm -lcfg -lpthread -o ipstat
#
#------------------------------------------------------------------------------
# Notes:
#   - Written and tested on AIX 7.1 TL 3 SP 4
#
#==============================================================================
*/

#if !defined(_AIX)
  #error "This program was written for AIX!"
#endif

#include <stdio.h>                      /* argv handling */
#include <math.h>                       /* ceil */
#include <locale.h>                     /* number formating */
#include <stdlib.h>                     /* number converting e.g. atoi */
#include <unistd.h>                     /* sleep && getuid */
#include <signal.h>                     /* interrupt handling */
#include <string.h>                     /* strncpy */
#include <errno.h>                      /* exit codes */
#include <sys/time.h>                   /* interval handling */
#include <arpa/inet.h>                  /* inet_ntoa */
#include <netinet/if_ether.h>           /* ethernet header */
#include <netinet/if_ether6.h>          /* ethernet header ip v6 */
#include <netinet/in.h>                 /* ip protocols */
#include <netinet/ip.h>                 /* ip header */
#include <netinet/ip6.h>                /* ip v6 header */
#include <netinet/udp.h>                /* udp header */
#include <netinet/tcp.h>                /* tcp header */
#include <netdb.h>                      /* get hostname */
#include <glib.h>                       /* hash table operations */
#include <pcap.h>                       /* pcap */
#include <ncurses/ncurses.h>            /* ncurses */
/*
----------------------------------------------------------------------------
   constants and macros
----------------------------------------------------------------------------
*/
#define SNAP_LEN 80                     /* 60 bytes max. IPv4 header length
                                           (IPv6 has default 40 bytes) +
                                           20 bytes for UDP/TCP header
                                           information
                                        */
#define MAX_CON 65534                   /* max tracked connections
                                           - too much monitored connections can
                                             have a performance impact and
                                             needs more memory
                                        */
#define BUFFER_SIZE 5242880             /* pcap buffer */
#define HASHSTR_LEN 128                 /* max length for hash string */
#define HOSTNAME_LEN 100                /* max length for hostname or ip */
#define FILTER_LEN 128                  /* max length of pcap filter */
#define MIN_WIDTH 80                    /* min terminal size */
#define MIN_HEIGHT 21
/*
----------------------------------------------------------------------------
   global variables and structs
----------------------------------------------------------------------------
*/
typedef struct {
  unsigned int interval;                /* refresh interval */
  unsigned int show_ports;              /* process ports */
  unsigned int show_udp;                /* ignore udp connections */
  unsigned int show_hostnames;          /* resolves IPs */
  unsigned int show_fqdn;               /* hostname without FQDN */
  unsigned int show_colors;             /* use ncurses colors */
  char sort[1];                         /* sort order */
  short color_pair_one;                 /* ncurses color handling */
  short color_pair_two;
  int color_bright;
}arguments;

typedef struct {                        /* used for sorting */
  unsigned int rindex;                  /* reference to connection array */
  time_t last_update;
  unsigned long long packets;
  unsigned long long size;
}sorting;

typedef struct {                        /* connection array */
    int ip_version;
    u_char protocol;
    u_short port_src;
    u_short port_dst;
    char con_src[INET6_ADDRSTRLEN];
    char con_dst[INET6_ADDRSTRLEN];
    unsigned long packets_src;
    unsigned long long size_src;
    unsigned long packets_dst;
    unsigned long long size_dst;
    u_char flags_src;
    u_char flags_dst;
}connection;

static pcap_t *handle;                  /* session handle */
static struct bpf_program fp;           /* compiled filter expression */

WINDOW *frame_con;                      /* ncurses windows */
WINDOW *frame_pac;
WINDOW *frame_byt;
WINDOW *frame_opt;
WINDOW *frame_sum;
WINDOW *frame_sta;
/*
----------------------------------------------------------------------------
   functions
----------------------------------------------------------------------------
*/
/*
****************************************************************************
*** interrupt handler / program close                                    ***
****************************************************************************
*/
void signal_handler(int signo) {
  delwin(frame_con);
  delwin(frame_pac);
  delwin(frame_byt);
  delwin(frame_opt);
  delwin(frame_sum);
  delwin(frame_sta);
  endwin();
  pcap_freecode(&fp);
  pcap_close(handle);
  exit(EXIT_SUCCESS);
}
/*
****************************************************************************
*** cleanup out of date stored connections to prevent memory leeks       ***
****************************************************************************
*/
void free_table_data(gpointer data) {
  free(data);
}
/*
****************************************************************************
*** calc time difference                                                 ***
****************************************************************************
*/
static int timersub(const struct timeval *a, const struct timeval *b,
                    struct timeval *res ) {
    long sec = a->tv_sec - b->tv_sec;
    long usec = a->tv_usec - b->tv_usec;

    if (usec < 0)
        usec += 1000000, --sec;

    res->tv_sec = sec;
    res->tv_usec = usec;

    return (sec < 0) ? (-1) : ((sec == 0 && usec == 0) ? 0 : 1);
}
/*
****************************************************************************
*** resolve tcp flags                                                    ***
****************************************************************************
*/
char *resolve_flags(u_char flags) {
  char *rflags = (char *) malloc(sizeof(char) * 7);
  memset(rflags, '\0', 7);
  if(flags & TH_FIN) {
    strcpy(rflags, "FINISH");
  } else if(flags & TH_RST) {
    strcpy(rflags, "RESET");
  } else {
    strcpy(rflags, "----");
    if(flags & TH_SYN) {
      /* initial sequence number */
      rflags[0] = 'S';
    }
    if(flags & TH_PUSH) {
      /* send data immediately */
      rflags[1] = 'P';
    }
    if(flags & TH_ACK) {
      /* acknowledgement */
      rflags[2] = 'A';
    }
    if(flags & TH_URG) {
      /* urgent */
      rflags[3] = 'U';
    }
  }
  return rflags;
}
/*
****************************************************************************
*** (incomplete) resolve of protocol types (netinet/in.h)                ***
****************************************************************************
 */
char *resolve_protocol(u_short protocol) {
  switch(protocol) {
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    default:           return "OTHER";
  }
}
/*
****************************************************************************
*** resolve hostnames                                                    ***
****************************************************************************
*/
char *resolve_hostname(arguments *config, int ip_version,
                       char host[INET6_ADDRSTRLEN]) {
  static GHashTable* hostnames = NULL;
  static int table_counter = 0;
  struct sockaddr_in sa;
  char *hostname = malloc(sizeof(char) * HOSTNAME_LEN);
  gpointer lookup;
  gpointer lookup_ptr = &lookup;
  int flag = 0;

  memset(hostname, '\0', HOSTNAME_LEN);
  strncpy(hostname, host, INET6_ADDRSTRLEN);

  if(config->show_hostnames) {
    /* hostname lookup table -> prevent dns requests for every new connection */
    if(!hostnames) {
      hostnames = g_hash_table_new_full(g_str_hash, g_str_equal,
                                        free_table_data, free_table_data);
    }

    if(g_hash_table_lookup_extended(hostnames, host, NULL,
                                    (gpointer *) lookup_ptr)) {
      strncpy(hostname, lookup, HOSTNAME_LEN);
    } else {
      if(!config->show_fqdn) {
        /* ignore domain part */
        flag = NI_NOFQDN;
      }
      /* get hostname */
      if(ip_version == AF_INET || ip_version == AF_INET6) {
        sa.sin_family = ip_version;
        inet_pton(ip_version, host, &sa.sin_addr);
        getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, HOSTNAME_LEN-1,
                    NULL, 0, flag);
        g_hash_table_insert(hostnames, g_strdup(host), g_strdup(hostname));
        table_counter += 1;
        if(table_counter > (MAX_CON*2)) {
          /* flush table to prevent memory overruns */
          g_hash_table_remove_all(hostnames);
          table_counter = 0;
        }
      }
    }
  }
  return hostname;
}
/*
****************************************************************************
*** draw windows ***
****************************************************************************
*/
void draw_windows(arguments *config) {
  unsigned int x, y;
  static unsigned int old_x = 0;
  static unsigned int old_y = 0;
  char placeholder[8];

  getmaxyx(stdscr, y, x);

  if(y < MIN_HEIGHT || x < MIN_WIDTH) {
    clear();
    mvprintw(0,0, "Abort: Terminal too small!");
    mvprintw(1,0, "Y:[%d/%d] X:[%d/80]", y, MIN_HEIGHT, x, MIN_WIDTH);
    refresh();
    sleep(5);
    signal_handler(0);
  }

  /* define window positions and sizes */
  const int CONH = y - 7;
  const int CONW = x - 46;
  const int CONY = 1;
  const int CONX = 0;

  const int PACH = y - 7;
  const int PACW = 15;
  const int PACY = 1;
  const int PACX = x - 46;

  const int BYTH = y - 7;
  const int BYTW = 23;
  const int BYTY = 1;
  const int BYTX = x - 31;

  const int OPTH = y - 7;
  const int OPTW = 8;
  const int OPTY = 1;
  const int OPTX = x - 8;

  const int SUMH = 3;
  const int SUMW = x;
  const int SUMY = y - 6;
  const int SUMX = 0;

  const int STAH = 3;
  const int STAW = x;
  const int STAY = y - 3;
  const int STAX = 0;

  /* create windows */
  if(x != old_x || y != old_y) {
    if(frame_con) { delwin(frame_con); }
    if(frame_pac) { delwin(frame_pac); }
    if(frame_byt) { delwin(frame_byt); }
    if(frame_opt) { delwin(frame_opt); }
    if(frame_sum) { delwin(frame_sum); }
    if(frame_sta) { delwin(frame_sta); }

    frame_con = newwin(CONH, CONW, CONY, CONX);
    frame_pac = newwin(PACH, PACW, PACY, PACX);
    frame_byt = newwin(BYTH, BYTW, BYTY, BYTX);
    frame_opt = newwin(OPTH, OPTW, OPTY, OPTX);
    frame_sum = newwin(SUMH, SUMW, SUMY, SUMX);
    frame_sta = newwin(STAH, STAW, STAY, STAX);

    /* draw header lines */
    attron(COLOR_PAIR(config->color_pair_one) | config->color_bright);
    mvprintw(0, 1, "IPStat");
    attroff(COLOR_PAIR(config->color_pair_one) | config->color_bright);

    old_x = x;
    old_y = y;
  }

  /* draw borders */
  wborder(frame_con, 0, ' ', 0, 0, 0, ACS_HLINE, 0, ACS_HLINE);
  wborder(frame_pac,' ',' ', 0, 0, ACS_HLINE, ACS_HLINE, ACS_HLINE, ACS_HLINE);
  wborder(frame_byt,' ',' ', 0, 0, ACS_HLINE, ACS_HLINE, ACS_HLINE, ACS_HLINE);
  wborder(frame_opt,' ',  0, 0, 0, ACS_HLINE, 0, ACS_HLINE, 0);
  box(frame_sum, 0, 0);
  box(frame_sta, 0, 0);

  /* draw header lines */
  if(config->show_ports) {
    mvwprintw(frame_con, 0 ,1,  " Connections (Host:Port) ");
  } else {
    mvwprintw(frame_con, 0, 1,  " Connections ");
  }

  getmaxyx(frame_pac, y, x);
  mvwprintw(frame_pac, 0, x - 10, " Packets ");
  getmaxyx(frame_byt, y, x);
  mvwprintw(frame_byt, 0, x - 8, " Bytes ");

  memset(placeholder, '\0', 7);
  if(!config->show_udp && config->show_ports) {
    strncpy(placeholder, " Flags ", 8);
  } else {
    strncpy(placeholder, " Type ", 7);
  }
  mvwprintw(frame_opt, 0, 0, "%s", placeholder);

  mvwprintw(frame_sum, 0, 1," Packet Summary ");
  mvwprintw(frame_sta, 0, 1," Statistics ");
}
/*
****************************************************************************
*** print connection informations                                        ***
****************************************************************************
*/
void print_connections(arguments *config, connection *cn, int line_counter) {
  unsigned int x;
  char *host_src;                         /* source hostname */
  char *host_dst;                         /* destination hostname */
  char *flags;                            /* pointer to address */

  x = getmaxx(frame_con);

  host_src = resolve_hostname(config, cn->ip_version, cn->con_src);
  host_dst = resolve_hostname(config, cn->ip_version, cn->con_dst);

  /* draw source -> target connector */
  wattron(frame_con,
          COLOR_PAIR(config->color_pair_two) | config->color_bright);
  mvwaddch(frame_con, line_counter,   1, ACS_ULCORNER);
  mvwaddch(frame_con, line_counter+1, 1, ACS_LLCORNER);
  wattroff(frame_con,
           COLOR_PAIR(config->color_pair_two) | config->color_bright);

  wattron(frame_con,
          COLOR_PAIR(config->color_pair_one) | config->color_bright);
  if(config->show_ports) {
    mvwprintw(frame_con,line_counter,   2, "%.*s:%d\n", x-9, host_src,
              cn->port_src);
    mvwprintw(frame_con,line_counter+1, 2, "%.*s:%d\n", x-9, host_dst,
              cn->port_dst);
  } else {
    mvwprintw(frame_con,line_counter,   2, "%.*s\n", x-3, host_src);
    mvwprintw(frame_con,line_counter+1, 2, "%.*s\n", x-3, host_dst);
  }
  wattroff(frame_con,
           COLOR_PAIR(config->color_pair_one) | config->color_bright);

  free(host_src);
  free(host_dst);

  wattron(frame_pac,
          COLOR_PAIR(config->color_pair_two) | config->color_bright);
  mvwprintw(frame_pac,line_counter,   0, "%'13d", cn->packets_src);
  mvwprintw(frame_pac,line_counter+1, 0, "%'13d", cn->packets_dst);
  wattroff(frame_pac,
           COLOR_PAIR(config->color_pair_two) | config->color_bright);

  wattron(frame_byt,
          COLOR_PAIR(config->color_pair_two) | config->color_bright);
  mvwprintw(frame_byt,line_counter,   0, "%'21llu", cn->size_src);
  mvwprintw(frame_byt,line_counter+1, 0, "%'21llu", cn->size_dst);
  wattroff(frame_byt,
           COLOR_PAIR(config->color_pair_two) | config->color_bright);

  wattron(frame_opt,
          COLOR_PAIR(config->color_pair_one) | config->color_bright);
  if(!config->show_udp && config->show_ports) {
    flags = resolve_flags(cn->flags_src);
    mvwprintw(frame_opt,line_counter,  0," %-6s",flags);
    free(flags);
    flags = resolve_flags(cn->flags_dst);
    mvwprintw(frame_opt,line_counter+1,0," %-6s",flags);
    free(flags);
  } else {
    mvwprintw(frame_opt,line_counter, 0," %-6s",
              resolve_protocol(cn->protocol));
  }
  wattroff(frame_opt,
           COLOR_PAIR(config->color_pair_one) | config->color_bright);
}
/*
****************************************************************************
*** print statistic informations                                         ***
****************************************************************************
*/
void print_statistics(arguments *config, unsigned long tcp, unsigned long udp,
                      unsigned long icmp, unsigned long others,
                      unsigned int total, double total_size, double seconds){

  struct pcap_stat stats;  /* pcap statistics */
  unsigned int index;      /* index for byte array */

  /* human readable bytes/sec reference */
  static char *bytes[] = { "B", "KB", "MB", "GB" };
  unsigned int x;

  x = getmaxx(frame_con);

  wattron(frame_sum,
          COLOR_PAIR(config->color_pair_one) | config->color_bright);
  mvwprintw(frame_sum, 1,  2,"TCP:");
  mvwprintw(frame_sum, 1, 20,"UDP:");
  mvwprintw(frame_sum, 1, 38,"ICMP:");
  mvwprintw(frame_sum, 1, 57,"Other:");
  wattroff(frame_sum,
           COLOR_PAIR(config->color_pair_one) | config->color_bright);
  wattron(frame_sum,
          COLOR_PAIR(config->color_pair_two) | config->color_bright);
  mvwprintw(frame_sum, 1,  6,"%'13d", tcp);
  mvwprintw(frame_sum, 1, 24,"%'13d", udp);
  mvwprintw(frame_sum, 1, 43,"%'13d", icmp);
  mvwprintw(frame_sum, 1, 63,"%'13d", others);
  wattroff(frame_sum,
           COLOR_PAIR(config->color_pair_two) | config->color_bright);

  /* calculate human readable transfer rate */
  index = 0;
  while (total_size > 1024 && index <= (sizeof(bytes)/sizeof(*bytes))) {
    total_size = total_size / 1024;
    index++;
  }
  wattron(frame_sta,
          COLOR_PAIR(config->color_pair_one) | config->color_bright);
  mvwprintw(frame_sta, 1,  2,"Packets/sec:");
  mvwprintw(frame_sta, 1, 33,"Througput:");
  wattroff(frame_sta,
           COLOR_PAIR(config->color_pair_one) | config->color_bright);

  wattron(frame_sta,
          COLOR_PAIR(config->color_pair_two) | config->color_bright);
  mvwprintw(frame_sta, 1, 15,"%'11.2f", (double) (total / seconds));
  mvwprintw(frame_sta, 1, 44,"%'8.2f %2s/s", (double) (total_size / seconds),
    bytes[index]);
  wattroff(frame_sta,
           COLOR_PAIR(config->color_pair_two) | config->color_bright);

  /* print extended statistic */
  x = getmaxx(frame_sum);
  if(x > 100 ) {
    pcap_stats(handle, &stats);
    wattron(frame_sum,
            COLOR_PAIR(config->color_pair_one) | config->color_bright);
    mvwprintw(frame_sum, 1, 77,"Dropped:");
    wattroff(frame_sum,
             COLOR_PAIR(config->color_pair_one) | config->color_bright);
    wattron(frame_sum,
            COLOR_PAIR(config->color_pair_two) | config->color_bright);
    mvwprintw(frame_sum, 1, 85,"%'13d", stats.ps_drop);
    wattroff(frame_sum,
             COLOR_PAIR(config->color_pair_two) | config->color_bright);
  }
}
/*
****************************************************************************
*** refresh windows                                                      ***
****************************************************************************
*/
void refresh_windows() {
  /* refresh screen */
  wnoutrefresh(stdscr);
  wnoutrefresh(frame_con);
  wnoutrefresh(frame_pac);
  wnoutrefresh(frame_byt);
  wnoutrefresh(frame_opt);
  wnoutrefresh(frame_sum);
  wnoutrefresh(frame_sta);
  doupdate();
}
/*
****************************************************************************
*** initialize ncurses                                                   ***
****************************************************************************
*/
void setup_initial_windows(arguments *config) {
  initscr();
  noecho();
  curs_set(FALSE);
  if(has_colors() && config->show_colors) {
    config->color_pair_one = 1;
    config->color_pair_two = 2;
    config->color_bright = A_BOLD;
    start_color();
    assume_default_colors(COLOR_CYAN, COLOR_BLUE);
    init_pair(config->color_pair_one, COLOR_YELLOW, COLOR_BLUE);
    init_pair(config->color_pair_two, COLOR_CYAN, COLOR_BLUE);
  } else {
    /* use default terminal colors */
    config->color_pair_one = 0;
    config->color_pair_two = 0;
    config->color_bright = A_NORMAL;
  }
  draw_windows(config);
  refresh_windows();
}
/*
****************************************************************************
*** functions for qsort                                                  ***
****************************************************************************
*/
int compare_update_time (const void *x,  const void *y) {
  sorting *time_x = (sorting *)x;
  sorting *time_y = (sorting *)y;
  return (time_y->last_update - time_x->last_update);
}
int compare_packets (const void *x,  const void *y) {
  sorting *time_x = (sorting *)x;
  sorting *time_y = (sorting *)y;
  return (time_y->packets - time_x->packets);
}
int compare_size (const void *x,  const void *y) {
  sorting *time_x = (sorting *)x;
  sorting *time_y = (sorting *)y;
  return (time_y->size - time_x->size);
}
/*
****************************************************************************
*** main callback function -> inspect and process pcap packet            ***
****************************************************************************
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  /*
     *** begin variable definition  ***
  */
  double seconds;                         /* seconds for refresh interval */
  unsigned long index = 0;                /* a index */
  unsigned long sindex = 0;               /* a second index */
  unsigned long rindex = 0;               /* another index */
  unsigned int found = FALSE;             /* true if con. is already known */
  unsigned int skip = FALSE;              /* true if con. should skipped */
  unsigned int line_counter = 1;          /* line counter for ncurses output */
  unsigned long payload = 0;              /* ip [tcp|udp] payload */
  int ip_version = 0;                     /* store IP Version */
  unsigned int y;                         /* terminal size */
  u_short port_src = 0;                   /* source port */
  u_short port_dst = 0;                   /* destination port */
  u_char tcp_flags = NULL;                /* store tcp flags */
  u_char protocol = NULL;                 /* store protocol (UDP,TCP,etc,) */
  char con_src[INET6_ADDRSTRLEN];         /* source address */
  char con_dst[INET6_ADDRSTRLEN];         /* destination address */
  char hash_src[HASHSTR_LEN];             /* connection hash string */
  char hash_dst[HASHSTR_LEN];             /* connection hash string */
  sorting t_array[MAX_CON];               /* temp. sorting values */
  gpointer lookup;                        /* for hash table lookup */
  gpointer lookup_ptr = &lookup;

  /* static variables */
  static struct timeval last_time;        /* used for refresh interval */
  static struct timeval curr_time;
  static struct timeval diff_time;
  static unsigned int total = 0;          /* packet and sizes counters */
  static double total_size = 0;
  static unsigned long icmp = 0;
  static unsigned long tcp = 0;
  static unsigned long udp = 0;
  static unsigned long others = 0;
  static unsigned int aindex = 0;         /* array/connection counter */
  static unsigned long control  = 0;      /* prevent variable overflows */
  static connection c_array[MAX_CON];     /* stores connection values */
  static sorting s_array[MAX_CON];        /* stores sorting values */
  static GHashTable* hash = NULL;         /* gnu hash table */

  /*
     *** end variable definition ***
  */

  /* create hash table */
  if(!hash) {
    hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                 free_table_data, free_table_data);
  }

  /* get arguments */
  arguments *config = (arguments *) args;

  /* get (and jump over) ethernet header */
  struct ether_header *eth = (struct ether_header *) packet;
  packet += sizeof(struct ether_header);

  /* evaluate IP version */
  switch (ntohs(eth->ether_type)) {
    case ETHERTYPE_IP:
    {
      /* get (and jump over) ip header */
      struct ip *iph = (struct ip*) packet;
      packet += sizeof(struct ip);
      /* get packet size */
      payload = iph->ip_len;
      protocol = iph->ip_p;
      ip_version = AF_INET;
      /* get ip */
      inet_ntop(AF_INET, &iph->ip_src, con_src, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &iph->ip_dst, con_dst, INET_ADDRSTRLEN);
      break;
    }
    case ETHERTYPE_IPV6:
    {
      /* get (and jump over) ip header */
      struct ipv6 *iph6 = (struct ipv6*) packet;
      packet += sizeof(struct ipv6);
      /* get packet size */
      payload = iph6->ip6_len;
      protocol = iph6->ip6_nh;
      ip_version = AF_INET6;
      /* get ip v6 */
      inet_ntop(AF_INET6, &iph6->ip6_src, con_src, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &iph6->ip6_dst, con_dst, INET6_ADDRSTRLEN);
      break;
    }
    default:
      /* nothing to process */
      return;
      break;
  }

  total++;
  control++;
  total_size += payload;

  /* evaluate protocol */
  /* get port header only if necessary, else ports are 0 */
  switch (protocol) {
    case IPPROTO_ICMP:
      icmp++;
      /* skip further processing icmp packets */
      if(config->show_ports) {
        skip = TRUE;
      }
      break;
    case IPPROTO_TCP:
      if(config->show_ports) {
        struct tcphdr *tcph = (struct tcphdr*) packet;
        port_src = tcph->th_sport;
        port_dst = tcph->th_dport;
        tcp_flags = tcph->th_flags;
      }
      tcp++;
      break;
    case IPPROTO_UDP:
      if(config->show_udp) {
        struct udphdr *udph = (struct udphdr*) packet;
        port_src = udph->uh_sport;
        port_dst = udph->uh_dport;
      } else if(config->show_ports) {
        skip = TRUE;
      }
      udp++;
      break;
    default: /* other protocol like ARP etc. */
      others++;
      /* skip further processing other packets */
      if(config->show_ports) {
        skip = TRUE;
      }
      break;
  }

  /* build hash string */
  snprintf(hash_src, HASHSTR_LEN, "%d %hhu %s %hu %s %hu",
           ip_version, protocol, con_src, port_src, con_dst, port_dst);
  snprintf(hash_dst, HASHSTR_LEN, "%d %hhu %s %hu %s %hu",
           ip_version, protocol, con_dst, port_dst, con_src, port_src);

  /* in mode 'show_ports' store only udp and tcp connections */
  if(!skip) {
    if(g_hash_table_lookup_extended(hash, hash_src, NULL,
                                   (gpointer *)lookup_ptr)) {
      index = GPOINTER_TO_INT(lookup);
      c_array[index].packets_src++;
      c_array[index].size_src += payload;
      c_array[index].flags_src = tcp_flags;
      found = TRUE;
    } else if(g_hash_table_lookup_extended(hash, hash_dst, NULL,
                                          (gpointer *)lookup_ptr)) {
      index = GPOINTER_TO_INT(lookup);
      c_array[index].packets_dst++;
      c_array[index].size_dst += payload;
      c_array[index].flags_dst = tcp_flags;
      found = TRUE;
    }
    /* if max connection is reached, overwrite the last updated one */
    if(found) {
      time(&s_array[index].last_update);
      s_array[index].packets++;
      s_array[index].size += payload;
    } else {
      if(aindex >= MAX_CON) {
        /* overwrite last updated connection */
        /* sort connections */
        memcpy(&t_array, &s_array, MAX_CON * sizeof(sorting));
        qsort(t_array, aindex, sizeof(sorting), compare_update_time);

        /* index = last updated connection */
        index = t_array[aindex-1].rindex;

        snprintf(hash_dst, HASHSTR_LEN, "%d %hhu %s %hu %s %hu",
                 c_array[index].ip_version, c_array[index].protocol,
                 c_array[index].con_src, c_array[index].port_src,
                 c_array[index].con_dst, c_array[index].port_dst);

        g_hash_table_remove(hash, hash_dst);
        aindex--;
      } else {
        index = aindex;
      }
      c_array[index].ip_version = ip_version;
      c_array[index].protocol = protocol;
      c_array[index].port_src = port_src;
      c_array[index].port_dst = port_dst;
      strncpy(c_array[index].con_src, con_src, INET6_ADDRSTRLEN);
      strncpy(c_array[index].con_dst, con_dst, INET6_ADDRSTRLEN);
      c_array[index].packets_src = 1;
      c_array[index].size_src = payload;
      c_array[index].packets_dst = 0;
      c_array[index].size_dst = 0;
      c_array[index].flags_src = tcp_flags;
      c_array[index].flags_dst = 0;
      time(&s_array[index].last_update);
      s_array[index].rindex = index;
      s_array[index].packets = 1;
      s_array[index].size = payload;
      g_hash_table_insert(hash, g_strdup(hash_src), GUINT_TO_POINTER(index));
      aindex++;

      if(aindex <= 0) {
        /* initialize variable last_time in first run */
        gettimeofday(&last_time, NULL);
      }
    }
  }

  /* time to print to terminal? */
  gettimeofday(&curr_time, NULL);
  timersub(&curr_time, &last_time, &diff_time);
  seconds = (double) diff_time.tv_sec;
  if( seconds >= config->interval) {
    draw_windows(config);

    /* sort connections */
    memcpy(&t_array, &s_array, MAX_CON * sizeof(sorting));

    if(strncmp(config->sort, "S", 1) == 0) {
      qsort(t_array, aindex, sizeof(sorting), compare_size);
    } else if(strncmp(config->sort, "P", 1) == 0) {
      qsort(t_array, aindex, sizeof(sorting), compare_packets);
    } else {
      qsort(t_array, aindex, sizeof(sorting), compare_update_time);
    }

    /* evaluate terminal output range */
    y = getmaxy(frame_con);
    if((aindex * 2) < (y - 2)) {
      sindex = aindex;
    } else {
      sindex = ceil((y - 2) / 2);
    }

    for(index = 0; index < sindex; index++) {
      rindex = t_array[index].rindex;
      print_connections(config, &c_array[rindex], line_counter);
      line_counter += 2;
    }

    print_statistics(config, tcp, udp, icmp, others, total, total_size,
                     seconds);
    refresh_windows();

    /* reset counters */
    total = 0;
    total_size = 0;

    /* update last time */
    gettimeofday(&last_time, NULL);
  }

  /* reset statistic counters to prevent integer overflows */
  if(control >= ULONG_MAX) {
    for(index = 0; index < aindex; index++) {
      c_array[index].packets_src = 0;
      c_array[index].size_src = 0;
      c_array[index].packets_dst = 0;
      c_array[index].size_dst = 0;
    }
    icmp = 0;
    tcp = 0;
    udp = 0;
    others = 0;
    control = 0;
  }
  return;
}
/*
****************************************************************************
*** help screen                                                          ***
****************************************************************************
*/
void help(char prog[]) {
  printf("\nUsage: %s %s\n\t%s\n\n", prog, "-d <device>",
    "[-f \"<filter>\"] [-i [1..30]] [-p] [-P] [-q] [-s [TPS]] [-u] [-c] [-h]");
  printf("\t-c\tuse colors\n");
  printf("\t-d\tdefine device, e.g. en0\n");
  printf("\t-f\tpcap/tcpdump filter, e.g. \"host foobar and port 22\" \n");
  printf("\t-h\tthis help\n");
  printf("\t-i\tset refresh interval in seconds (default: 2)\n");
  printf("\t-n\tshow hostnames instead of IPs\n");
  printf("\t-p\tshow TCP connections with ports\n");
  printf("\t-P\tenable promiscuous mode\n");
  printf("\t-q\tshow hostnames with FQDN (implies -n)\n");
  printf("\t-s\tset sort order, [T]ime, [P]ackets, [S]ize (default: T)\n");
  printf("\t-u\tshow TCP and UDP connections with ports (implies -p)\n\n");
  exit(EXIT_FAILURE);
}
/*
----------------------------------------------------------------------------
   main program
----------------------------------------------------------------------------
*/
int main(int argc, char* argv[]) {
  char *device;                /* device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];    /* error string */
  char filter_exp[FILTER_LEN];          /* filter expression */
  int promiscuous = FALSE;              /* promiscuous mode */

  arguments *config = malloc(sizeof(arguments));

  config->interval = 2;                 /* refresh interval */
  config->show_ports = FALSE;           /* process ports */
  config->show_udp = FALSE;             /* ignore udp connections */
  config->show_hostnames =FALSE;        /* show hostnames */
  config->show_fqdn = FALSE;            /* show FQDN */
  config->show_colors = FALSE;          /* use ncurses colors */

  if(getuid() != 0 ){
    printf("\nThis program must be run as root.\n\n");
    exit(EXIT_FAILURE);
  }

  /* interrupt handler */
  signal(SIGINT, signal_handler);

  /* set number format */
  setlocale(LC_NUMERIC, "");

  memset(filter_exp, '\0', 128);
  strncpy(filter_exp, "ip or ip6\0", 10);

  int OPTION = 0;
  while ((OPTION = getopt(argc, argv,"cd:f:hi:npPqs:u")) != -1) {
    switch (OPTION) {
      case 'c' : config->show_colors = TRUE;
                 break;
      case 'd' : device = (char *) optarg;
                 break;
      case 'f' : if(strlen(optarg) >= FILTER_LEN) {
                   fprintf(stderr, "\n  Filter expression too long!\n");
                   fprintf(stderr, "    Max. [%d] characters allowed.\n\n",
                           FILTER_LEN);
                   exit(EXIT_FAILURE);
                 }
                 strncpy(filter_exp,(char *) optarg, FILTER_LEN);
                 break;
      case 'h' : help(argv[0]);
                 break;
      case 'i' : config->interval = (unsigned int) atoi(optarg);
                 if(config->interval < 1 || config->interval > 30) {
                   fprintf(stderr, "\n  Interval is out of range!\n\n");
                   exit(EXIT_FAILURE);
                 }
                 break;
      case 'n' : config->show_hostnames = TRUE;
                 break;
      case 'p' : config->show_ports = TRUE;
                 break;
      case 'P' : promiscuous = TRUE;
                 break;
      case 'q' : config->show_fqdn = TRUE;
                 config->show_hostnames = TRUE;
                 break;
      case 's' : strncpy(config->sort, (char *) optarg, 1);
                 if(strncmp(config->sort, "T", 1) != 0 &&
                    strncmp(config->sort, "P", 1) != 0 &&
                    strncmp(config->sort, "S", 1) != 0) {
                   fprintf(stderr, "\n  Unknown sort order!\n\n");
                   exit(EXIT_FAILURE);
                 }
                 break;
      case 'u' : config->show_udp = TRUE;
                 config->show_ports = TRUE;
                 break;
      default :  help(argv[0]);
    }
  }

  if(device == NULL ) {
    fprintf(stderr, "\n  No device specified!\n\n");
    help(argv[0]);
  }

  if((handle = pcap_create(device, errbuf)) == NULL) {
    fprintf(stderr, "\nCouldn't create handle for device %s: %s\n\n",
            device, errbuf);
    exit(EXIT_FAILURE);
  }
  if(pcap_set_snaplen(handle, SNAP_LEN) < 0) {
    fprintf(stderr, "\nCouldn't set SNAP_LEN for handle!\n\n");
    exit(EXIT_FAILURE);
  }
  if(pcap_set_promisc(handle, promiscuous) < 0) {
    fprintf(stderr, "\nCouldn't set promiscuous mode for handle!\n\n");
    exit(EXIT_FAILURE);
  }
  if(pcap_set_timeout(handle, 1000) < 0) {
    fprintf(stderr, "\nCouldn't set timeout for handle!\n\n");
    exit(EXIT_FAILURE);
  }
  if(pcap_set_buffer_size(handle, BUFFER_SIZE) < 0) {
    fprintf(stderr, "\nCouldn't set buffer size for handle!\n\n");
    exit(EXIT_FAILURE);
  }
  pcap_activate(handle);

  /* make sure we're capturing on an Ethernet device */
  if (pcap_datalink(handle) != DLT_EN10MB) {
   fprintf(stderr, "\n Device %s is not an Ethernet!\n\n", device);
     exit(EXIT_FAILURE);
  }

  /* compile the filter expression */
  /*
     # Linux man page -  pcap_compile:
     # -------------------------------
     # netmask specifies the IPv4 netmask of the network on which packets
     # are being captured; it is used only when checking for IPv4 broadcast
     # addresses in the filter program.
     # If the netmask of the network on which packets are being captured
     # isn't known to the program, or if packets are being captured on
     # the Linux "any" pseudo-interface that can capture on more
     # than one network, a value of PCAP_NETMASK_UNKNOWN can be supplied;
     # tests for IPv4 broadcast addreses will fail to compile, but all
     # other tests in the filter program will be OK.
  */
  if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "\nCouldn't parse filter %s: %s\n\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "\nCouldn't install filter %s: %s\n\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* initialize ncurses */
  setup_initial_windows(config);

  /* set callback function */
  pcap_loop(handle, -1, got_packet, (u_char *)config);

  /* cleanup and exit */
  signal_handler(0);
  return(0);
}