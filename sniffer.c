#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <linux/udp.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};

struct ring {
	struct iovec *rd;
	uint8_t *map;
	struct tpacket_req3 req;
};

static unsigned long packets_total = 0, bytes_total = 0;
static sig_atomic_t sigint = 0;

static void sighandler(int num)
{
	sigint = 1;
}

static int setup_socket(struct ring *ring, char *netdev)
{
	int err, i, fd, v = TPACKET_V3;
	struct sockaddr_ll ll;
	unsigned int blocksiz = 1 << 22, framesiz = 1 << 11;
	//unsigned int blocksiz = 1 << 12;
	//unsigned int framesiz = 1 << 9;
	//unsigned int framesiz = 0x110;
	unsigned int blocknum = 128;
	//unsigned int blocknum = 32;
// was SOCK_RAW
// wasETH_P_ALL
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("socket");
		exit(1);
	}
	printf("-setup_socket: post socket \n");

	err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}
	printf("-setup_socket: post setsockopt PACKET_VERSION \n");

	memset(&ring->req, 0, sizeof(ring->req));

	ring->req.tp_block_size = blocksiz;
	ring->req.tp_frame_size = framesiz;
	ring->req.tp_block_nr = blocknum;
	ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
	ring->req.tp_retire_blk_tov = 60;
	ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

printf("ring->req.tp_frame_size: %d\n", ring->req.tp_frame_size);
printf("ring->req.tp_frame_nr: %d\n",   ring->req.tp_frame_nr);
printf("ring->req.tp_block_size: %d\n", ring->req.tp_block_size);
printf("ring->req.tp_block_nr: %d\n",   ring->req.tp_block_nr);

	err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req,
			 sizeof(ring->req));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}
	printf("-setup_socket: post setsockopt PACKET_RX_RING \n");
// remove MAP_LOCKED
	//ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
	//		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
	ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
			 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring->map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	printf("-setup_socket: post mmap \n");

	ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
	assert(ring->rd);
	for (i = 0; i < ring->req.tp_block_nr; ++i) {
		ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
		ring->rd[i].iov_len = ring->req.tp_block_size;
	}
		printf("-setup_socket: post malloc \n");

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
// was ETH_P_ALL
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_ifindex = if_nametoindex(netdev);
	ll.sll_hatype = 0;
	ll.sll_pkttype = 0;
	ll.sll_halen = 0;

	err = bind(fd, (struct sockaddr *) &ll, sizeof(ll));
	if (err < 0) {
		perror("bind");
		exit(1);
	}
	printf("-setup_socket: post bind \n");
	
	return fd;
}


static void display(struct tpacket3_hdr *ppd, char *dis_proto)
{
	printf("--------------------------------------\n");
	// linux/if_ether.h
/*
struct ethhdr {
        unsigned char   h_dest[ETH_ALEN];       // destination eth addr
        unsigned char   h_source[ETH_ALEN];     // source ether addr 
        __be16          h_proto;                // packet type ID field
} __attribute__((packed));
#define ETH_ALEN        6               // Octets in one ethernet addr
#define ETH_HLEN        14              // Total octets in header.   
*/
	///////////////////
	// MAC Header
	///////////////////
	struct ethhdr *eth = (struct ethhdr *) ((uint8_t *) ppd + ppd->tp_mac);
	printf("-display: ppd address:  %p\n", (void *)ppd);
	printf("-display: eth address:  %p\n", (void *)eth);
	printf("-display: eth->h_dest:   ");
	int i;
	for ( i=0; i < ETH_ALEN; i++) {
		//printf((i<start)?"   ":"%02x%c",
        //             (unsigned char)ps_header_start[i],((i+1)&15)?' ':'\n');
		printf("%02x ", (unsigned char ) eth->h_dest[i]);
	}
	printf("\n");
	printf("-display: eth->h_source: ");
	for ( i=0; i < ETH_ALEN; i++) {
		printf("%02x ", (unsigned char ) eth->h_source[i]);
	}
	printf("\n");

	printf("-display: eth->h_proto %x\n", (__be16 ) eth->h_proto);

/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __be16  tot_len;
        __be16  id;
        __be16  frag_off;
        __u8    ttl;
        __u8    protocol;
        __sum16 check;
        __be32  saddr;
        __be32  daddr;
        // The options start here.
};
*/
#define	UDP_PROTOCOL	17
#define	TCP_PROTOCOL	6
#define ICMP_PROTOCOL	1
#define UDP_HLEN		8
#define ICMP_HLEN		8
	/////////////////////
	// IP Header
	/////////////////////
	struct iphdr *ip = (struct iphdr *) ((uint8_t *) eth + ETH_HLEN);
	printf("-display: ip address:  %p\n", (void *)ip);

		//if (ip->protocol != 17 && ip->protocol != 1) {
			printf("-display: ip->version %d\n",	 (__u8 )ip->version);
			printf("-display: ip->ihl %d 32-bit words\n", (__u8 )ip->ihl);
			printf("-display: ip->tos %d\n",	     (__u8 )ip->tos);
			printf("-display: ip->tot_len 0x%x\n",   (__be16 )ip->tot_len);
			printf("-display: ip->id  0x%x\n", 	     (__be16 )ip->id);
			printf("-display: ip->frag_off  0x%x\n", (__be16 )ip->frag_off);
			printf("-display: ip->ttl %d\n",         (__u8 )ip->ttl);
			printf("-display: ip->protocol %d\n",    ip->protocol);
			printf("-display: ip->check  0x%x\n",    (__sum16 )ip->check);
			printf("-display: ip->saddr  0x%x\n",    (__be32 )ip->saddr);
			printf("-display: ip->daddr  0x%x\n",    (__be32 )ip->daddr);

	char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];


	// ETH_P_IP
	if (eth->h_proto == htons(ETH_P_IP)) {
		//printf("-display:  in h_proto ETH_P_IP\n");
		struct sockaddr_in ss, sd;
		//char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];

		memset(&ss, 0, sizeof(ss));
		ss.sin_family = PF_INET;
		ss.sin_addr.s_addr = ip->saddr;
		getnameinfo((struct sockaddr *) &ss, sizeof(ss),
			    sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);

		memset(&sd, 0, sizeof(sd));
		sd.sin_family = PF_INET;
		sd.sin_addr.s_addr = ip->daddr;
		getnameinfo((struct sockaddr *) &sd, sizeof(sd),
			    dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);

		printf("%s -> %s, ", sbuff, dbuff);
	}

	printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);

/*
struct udphdr {
        __be16  source;
        __be16  dest;
        __be16  len;
        __sum16 check;
};
*/
	////////////////
	// UDP Header
	/////////////////
	struct udphdr *udp;
	udp = (struct udphdr *) ((uint8_t *) ip + (ip->ihl * 4));
	printf("-display: udp address:  %p\n", (void *)udp);

	printf("-display: udp->source 0x%x\n", (__be16 )udp->source);
	printf("-display: udp->dest  0x%x\n",  (__be16 )udp->dest);
	printf("-display: udp->len  0x%x\n",   (__be16 )udp->len);
	printf("-display: udp->check  0x%x\n", (__sum16 )udp->check);


/*
struct icmphdr {
  __u8          type;
  __u8          code;
  __sum16       checksum;
  union {
        struct {
                __be16  id;
                __be16  sequence;
        } echo;
        __be32  gateway;
        struct {
                __be16  __unused;
                __be16  mtu;
        } frag;
  } un;
};
*/
	////////////////
	// ICMP Header
	/////////////////
	struct icmphdr *icmp;
	icmp = (struct icmphdr *) ((uint8_t *) ip + (ip->ihl * 4));
	if (ip->protocol == 1) {
			// ip->ihl holds the number of 32-bit words
			//icmp = (struct icmphdr *) ((uint8_t *) ip + (ip->ihl * 4));
			printf("-display: icmp address:  %p\n", (void *)icmp);
			printf("-display: icmp->type %d\n", (__u8 )icmp->type);
			printf("-display: icmp->code %d\n", (__u8 )icmp->code);
			printf("-display: icmp->checksum %d\n", (__sum16 )icmp->checksum);
			printf("-display: ip->tot_len 0x%x\n",   (__be16 )ip->tot_len);
	}
	
	/////////////
	// DATA
	/////////////
	// if a TCP or ICMP packet, data should be after (ip>ihl * 4), else
	// if UDP is should be after the udp header 12 + 64 bytes (udp header size)
	// data length should be tot_len - ihl
	volatile int data_len = 0;
	volatile int data_offset = 0;

	char * udp_data;
	char * icmp_data;
	char * tcp_data;
	if(ip->protocol == 17) {
		data_len = udp->len - 8;
		printf("-display: data_len 0x%x\n",   (__be16 )data_len);
	
		data_offset = UDP_HLEN;
		
		// data for UDP 
		udp_data = (void *) ((uint8_t *) udp + data_offset);
		printf("-display: udp_data address:  %p\n", (void *)udp_data);
	} else  {
		//data_len = ip->tot_len - (ip->ihl * 4);
		data_len = ip->tot_len;
		printf("-display: data_len 0x%x\n",   (__be16 )data_len);
	
		if (ip->protocol == 1) {
			// ICMP_HLEN is 8 bytes
			data_offset = ICMP_HLEN;
			icmp_data = (void *) ((uint8_t *) icmp + data_offset);
			printf("-display: icmp_data address:  %p\n", (void *)icmp_data);
			
		} else {
			// ip->ihl holds the number of 32-bit words
			data_offset = (ip->ihl * 4);
			tcp_data = (void *) ((uint8_t *) ip + data_offset);
			printf("-display: tcp_data address:  %p\n", (void *)tcp_data);
		}
	}
	printf("-display: data_offset 0x%x\n",   (__be16 )data_offset);
	printf("-display: udp_data address:  %p\n", (void *)udp_data);

	/////////////////////////////
	//
	//		PACKET DUMP
	//
	//////////////////////////////
	int start = 0;
	printf("================= data [0-512] ==================\n");
	char * data;
if (ip->protocol == 17) {
	
	if (strcmp((const char *)dis_proto, "data") == 0) {
		//data = (void *)udp_data;
		data = (void *) ((uint8_t *) udp + UDP_HLEN);
	} else if (strcmp((const char *)dis_proto, "udp") == 0) {
		data = (void *)udp;
	} else if (strcmp((const char *)dis_proto, "icmp") == 0) {
		data = (void *)icmp;
	} else if (strcmp((const char *)dis_proto, "ip") == 0) {
		data = (void *)ip;
	} else if (strcmp((const char *)dis_proto, "eth") == 0) {
		data = (void *)eth;
	} else if (strcmp((const char *)dis_proto, "ppd") == 0) {
		data = (void *)ppd;
	} else {
		perror("unkown protocol to start hex dump");
		exit(1);
	}
	printf("Starting HEX dump for %s at %p\n", dis_proto, (void *)data);
	printf("-------------------------------------------------------\n");
	for (i=0; i < data_len; i++) {
		//printf((i<start)?"   ":"%02x%c",
        //	(unsigned char)ps_header_start[i],((i+1)&15)?' ':'\n');
        printf((i<start)?"   ":"%02x%c",
        	(unsigned char)data[i],((i+1)&15)?' ':'\n');
        if (i > 512) {
        	printf("\n-display: more than 512 bytes, aborting dump.\n");
        	break;
        }
	}
}
	printf("================================================\n");

	printf("--------------------------------------\n");
}
/*
struct tpacket_hdr_variant1 {
        __u32   tp_rxhash;
        __u32   tp_vlan_tci;
};

struct tpacket3_hdr {
        __u32           tp_next_offset;
        __u32           tp_sec;
        __u32           tp_nsec;
        __u32           tp_snaplen;
        __u32           tp_len;
        __u32           tp_status;
        __u16           tp_mac;
        __u16           tp_net;
        // pkt_hdr variants
        union {
                struct tpacket_hdr_variant1 hv1;
        };
};
*/
static void walk_block(struct block_desc *pbd, const int block_num, char *dis_proto)
{
	int num_pkts = pbd->h1.num_pkts, i;
	unsigned long bytes = 0;
	struct tpacket3_hdr *ppd;

	ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
				       pbd->h1.offset_to_first_pkt);
	for (i = 0; i < num_pkts; ++i) {
		bytes += ppd->tp_snaplen;
		printf("-walk_block: pre display  \n");
		display(ppd, dis_proto);
		printf("-walk_block: post display  \n");

		ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
					       ppd->tp_next_offset);
	}

	packets_total += num_pkts;
	bytes_total += bytes;
}

static void flush_block(struct block_desc *pbd)
{
	pbd->h1.block_status = TP_STATUS_KERNEL;
}

static void teardown_socket(struct ring *ring, int fd)
{
	munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
	free(ring->rd);
	close(fd);
}

int main(int argc, char **argp)
{
	int fd, err;
	socklen_t len;
	struct ring ring;
	struct pollfd pfd;
	unsigned int block_num = 0, blocks = 64;
	struct block_desc *pbd;
	struct tpacket_stats_v3 stats;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s INTERFACE dispaly[udp|tcp|icmp]\n", argp[0]);
		return EXIT_FAILURE;
	}

	signal(SIGINT, sighandler);

	memset(&ring, 0, sizeof(ring));
	printf("-main: pre setup_socket \n");
	//fd = setup_socket(&ring, argp[argc - 1]);
	fd = setup_socket(&ring, argp[1]);
	printf("-main: post setup_socket \n");
	assert(fd > 0);

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;

	while (likely(!sigint)) {
		pbd = (struct block_desc *) ring.rd[block_num].iov_base;

		if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
			poll(&pfd, 1, -1);
			continue;
		}
		printf("-main: pre walk_block \n");
		//walk_block(pbd, block_num, argp[argc - 2]);
		walk_block(pbd, block_num, argp[2]);
		printf("-main: post walk_block \n");
		flush_block(pbd);
		block_num = (block_num + 1) % blocks;
	}

	len = sizeof(stats);
	err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	if (err < 0) {
		perror("getsockopt");
		exit(1);
	}
	printf("-main: post getsockopt PACKET_STATISTICS \n");

	fflush(stdout);
	printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
	       stats.tp_packets, bytes_total, stats.tp_drops,
	       stats.tp_freeze_q_cnt);

	teardown_socket(&ring, fd);
	printf("-main: post teardown_socket \n");
	return 0;
}


