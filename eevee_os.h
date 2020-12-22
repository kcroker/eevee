/*
 * eevee_os.h
 * Copyright(c) 2018 Kevin Croker, Kurtis Nishimura
 *
 * Header file contains prototypes, defines and structures pulled verbatim from
 * standard POSIX and Linux /usr/includes
 *
 */


#ifndef EEVEE_OS_H
#define EEVEE_OS_H

#include <unistd.h>
#include "xil_types.h"

#include "platform_definition.h"

// Platform specific annoyances.
#ifdef SPARTAN6
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_int32_t;
typedef unsigned long uint32_t;
#endif

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128

/*
 * http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
 */
typedef u_int32_t ip4_t;

typedef struct dhcp
{
    u_int8_t    opcode;
    u_int8_t    htype;
    u_int8_t    hlen;
    u_int8_t    hops;
    u_int32_t   xid;
    u_int16_t   secs;
    u_int16_t   flags;
    ip4_t       ciaddr;
    ip4_t       yiaddr;
    ip4_t       siaddr;
    ip4_t       giaddr;
    u_int8_t    chaddr[DHCP_CHADDR_LEN];
    char        bp_sname[DHCP_SNAME_LEN];
    char        bp_file[DHCP_FILE_LEN];
    uint32_t    magic_cookie;
    u_int8_t    bp_options[0];
} dhcp_t;

#define DHCP_BOOTREQUEST                    1
#define DHCP_BOOTREPLY                      2

#define DHCP_HARDWARE_TYPE_10_EHTHERNET     1

#define MESSAGE_TYPE_PAD                    0
#define MESSAGE_TYPE_REQ_SUBNET_MASK        1
#define MESSAGE_TYPE_ROUTER                 3
#define MESSAGE_TYPE_DNS                    6
#define MESSAGE_TYPE_DOMAIN_NAME            15
#define MESSAGE_TYPE_REQ_IP                 50
#define MESSAGE_TYPE_DHCP                   53
#define MESSAGE_TYPE_SELECTED_SERVER        54
#define MESSAGE_TYPE_PARAMETER_REQ_LIST     55
#define MESSAGE_TYPE_END                    255

#define DHCP_OPTION_DISCOVER                1
#define DHCP_OPTION_OFFER                   2
#define DHCP_OPTION_REQUEST                 3
#define DHCP_OPTION_DECLINE                 4
#define DHCP_OPTION_ACK                     5
#define DHCP_OPTION_NAK                     6

// wtf is this, guy?
//#define DHCP_OPTION_PACK                    4

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_MAGIC_COOKIE   0x63825363

/*  
 * KC 10/18/18
 *
 * This is just quick and dirty.  I've pasted from the standard POSIX/libc headers
 * And changed wonky typedef things to just bare types.
 *
 * Many of these header files look like they can be imported verbatim, though
 * somewhat simplified.
 *
 */

/* Things from various header files that are needed for ethernet, ip, and udp */
/* These were things that I didn't look hard for because I know what they are... */
#define ETH_ALEN 6
#define IPVERSION 4

// From: net/ethernet.h
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  u_int16_t ether_type;		        /* packet type ID field	*/
} __attribute__ ((__packed__));

#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHER_ADDR_LEN	ETH_ALEN                 /* size of ethernet addr */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */

// From: netinet/in.h
typedef u_int32_t in_addr_t;

struct in_addr
{  
  in_addr_t s_addr;
}; // __attribute__ ((aligned(4)));

#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

// From: netinet/ip.h
/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */

/*
 * Structure of an internet header, naked of options.
 */
/* Note, this is not what LITTLE_ENDIAN is in the POSIX/Linux headers... */
// But the uBlaze is little endian */
#define __LITTLE_ENDIAN 666
#define __BYTE_ORDER __LITTLE_ENDIAN

#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */

struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#endif
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};

// From: netinet/udp.h
/* UDP header as specified by RFC 768, August 1980. */

struct udphdr
{
  __extension__ union
  {
    struct
    {
      u_int16_t uh_sport;		/* source port */
      u_int16_t uh_dport;		/* destination port */
      u_int16_t uh_ulen;		/* udp length */
      u_int16_t uh_sum;		/* udp checksum */
    };
    struct
    {
      u_int16_t source;
      u_int16_t dest;
      u_int16_t len;
      u_int16_t check;
    };
  };
};

//
// Now we import lowlevel FSL ether reads and writes from Kurtis
//

// From: ethPackets.h

// Ethernet Frame
#define ETH_HEADER_SIZE 14
struct EthFrame {

  // Start porting this over to standard stuff
  struct ether_header eheader;
  u8  payload[ETH_MTU - ETH_HEADER_SIZE];
} __attribute__ ((aligned(2)));


// From: linux/if_arp.h
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/

// I think this means big endian...
typedef u16 __be16;

struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/
  //#if 0
	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
  //#endif
};

// From netinet/ip_icmp.h

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_ECHO		8	/* Echo Request			*/

struct icmphdr
{
  u_int8_t type;                /* message type */
  u_int8_t code;                /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t id;
      u_int16_t sequence;
    } echo;                     /* echo datagram */
    u_int32_t   gateway;        /* gateway address */
    struct
    {
      u_int16_t __glibc_reserved;
      u_int16_t mtu;
    } frag;                     /* path mtu discovery */
  } un;
};


// KC 10/20/18
//
// Technically, this should be a linked list of arp entries.
// They should be sorted as new entries are added, so that
// lookups are log N
//
// Super overkill ;)
//
struct NIFT_arp {

  // Store these in Network order for fast use
  struct in_addr ipaddr_n;
  u8 mac_n[6];
};

// Support a maximum of 10 devices for now
#define ARP_TABLE_LEN 10

struct NIFT_ip {

  // For Layer 2
  // This is already stored in network order it seems ;)
  u8 mac[6];
  struct NIFT_arp arpTable[ARP_TABLE_LEN];
  u8 arpTableNext;

  // For Layer 3
  ip4_t ip;
  ip4_t dhcpserver;
  ip4_t gateway;
  ip4_t subnet_mask;

  // For caching registers where changes need to be processed
  ip4_t nbic_destip;
  
  // Status flag: 0 - nope, 1 - in process, 2 - good to go
  u8 configured;
};


struct NIFT_source {

  u8 smacn[ETH_ALEN];
  struct in_addr sip;
  u16 sport;
};

//
// Version: cafeXXXX
// Status: in development from 1/24/19
//
struct eevee_register {

  u32 addr;
  u32 word;
};
  
struct eevee_payload {

  //
  // So that many registers can be set at once without wasting an additional u32
  // each time.
  //
  // If op & EEVEE_OP_MASK_REG, then the following interpretation:
  //   width = N*sizeof(struct eevee_register)
  //   payload contains N eevee_register structures
  //   op & EEVEE_OP_MASK_OTHER = 0x0
  // If any of the checks fail, the operation is silently ignored.
  //
  // If op & EEVEE_OP_MASK_SILENT, then this operation will
  // not be echoed in the transaction response
  //
  // If op & EEVEE_OP_MASK_OTHER, then
  //    board specific controls can be implemented.
  //    op & EEVEE_OP_MASK_REG = 0x0
  // If the check fails, the operation is silently ignored
  //
  u16 op;
  u16 width;

  // This zero length array trick is super cute: it gives a pointer
  // to the end of the structure.  It does NOT allocate space for
  // a single pointer within the structure.
  u8 payload[0];
};

//
// Since we don't do fragmented packets...
// And we are restricting ourselves to ethernet packets...
//
struct eevee {

  // Because everyone else is doing it.
  u32 magic;

  // Checks the version against that in the regmap
  // so that you don't cause boards to bzzz themselves due to
  // insane requests.
  //
  // This version is now split into 2 u16:
  //   version & 0x0000FFFF = software version
  //   version & 0xFFFF0000 >> 16 = hardware version
  //
  u32 version;

  //
  // A sequence number
  // Set by the client and incremented by the board.
  // No state is preserved wrt this number.
  // So if someone requests a silent operation, you'll never get an increment
  u32 seqnum;

  // Do less offset munging
  struct eevee_payload transaction[0];
  
  //   -- DATABLOCK --
};


//////////////// NEW STUFF FOR EXTENSIONS       /////////
//////////////// (and incremental improvements) /////////
// KC  6/17/19

struct NIFT_eevee {

  u32 version;

#ifdef EEVEE_STONES
  struct eevee_stone *stones;
#endif
};

///////////////////////// Function Prototypes ///////////////////////
int dhcp_request(void);
void ether_output(u8 *frame, u8 *dmacn, short ethertype, int len);
void eevee_input(struct NIFT_source *source, struct eevee *eeveehdr_in, int transaction_len);
void ip_output(struct ip *ip_header, u32 dst, int proto, int *len);
void udp_output(struct udphdr *udp_header, u16 sport, u16 dport, int *len);
void icmp_input(struct NIFT_source *source, struct icmphdr *icmp_packet, struct ip *ip_packet);
int arp_cache_resolve(u32 ip, u8 *mac);
void arp_cache_push(u32 ip, u8 *mac);

u8 *mallocPacket(u16 size);
int transmitPacket(u8 *packet, u16 src_port, u32 dest_ip, u16 dest_port, int unwrapped_length);
void freePacket(u8 *packet);

///////////////////////// Critical defines //////////////////
// Use convention where macros are uppercase
// ??? I don't think these should have had semicolons after them...
#define NISHI_REG_READ(into, where) ((into) = *( (u32 *)(XPAR_IOMODULE_0_IO_BASEADDR | (where))) )
#define NISHI_REG_WRITE(where, what) ( *( (u32 *)(XPAR_IOMODULE_0_IO_BASEADDR | (where))) = (what) )
#define DISPLACE(addr, obj) ( (u8 *) ( ((u8 *)addr) + sizeof(obj) ) ) 
#endif
