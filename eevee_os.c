/*
 * eevee_os.c
 * Copyright(c) 2018 Kevin Croker, Kurtis Nishimura
 *
 * Adapted code from Samuel Jacob (samueldotj@gmail.com) (dhcp-client simple)
 *
 */

// Includes for ublaze
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include "fsl.h"
#include "xil_types.h"
#include "xil_io.h"

#include "eevee_os.h"
#include "eevee_regmap.h"
#include "eevee_control.h"

#include "eevee_stones.h"
#include "eevee_telemetry_stone.h"


// From: ethMain.c

// Hax to place the ethernet payload itself on a 4-byte alignment
#define ETH_PAYLOAD_ALIGNMENT_SHIFT 2

// Buffers for input data
u8 gInboundData_buffer[ETH_MTU + ETH_PAYLOAD_ALIGNMENT_SHIFT];
u8 *gInboundData;
struct EthFrame *gInboundFrame;

// Variables for tracking incoming data buffer positions and status
u32 gInboundWordPos = 0;
u32 gCompletePacket = 0;
u32 *gpInboundFrame;

// Now some internal structures I use for keeping track of myself
struct NIFT_ip NIFT_ipsystem;
struct NIFT_eevee eevee;

#define RESET_FRAME() (gInboundWordPos = gCompletePacket = 0, gpInboundFrame = (u32 *)gInboundData)

/* void resetFrame(void) { */
/*   gInboundWordPos = 0; */
/*   gCompletePacket = 0; */

/*   memset((void *) gInboundData, 0, ETH_MTU + ETH_PAYLOAD_ALIGNMENT_SHIFT); */
/*   gpInboundFrame = (u32 *) gInboundData; */
/* } */

//
// If this is not run, then the fsl_iserror()
// will always adjust its argument so as to suggest that the a packet is complete
//
void clearLast() {
	u32 msrData = mfmsr();
	msrData &= ~0x10;
	mtmsr(msrData);
}

// Reads a single word off of a given channel
// KC 10/18/18: changed to a single channel for now.
// later, abstract this.
void readFsl(void) {

  register u32 tempInvalid = 0;
  register u32 tempLast = 0;
  u32 tempData = 0;

  // This is a macro to some ublaze assembly it seems... (UG081)
  getfslx(tempData, 0, FSL_NONBLOCKING);

  // OOO: These must be macros, since they mutate the values given as arguments
  fsl_isinvalid(tempInvalid);

  // Checks Microblaze machine status register (MSR) bit 27
  fsl_iserror(tempLast);
  
  // Copy the data (if possible) and update the word position if data was good
  if (!tempInvalid) {

    // If we can accept a word, write it
    if (gInboundWordPos < ETH_MTU_D4)
      //*gpInboundFrame = tempData;
      memcpy(gpInboundFrame, &tempData, 4);

    // Always increment
    ++gInboundWordPos;
    ++gpInboundFrame;
  }

  // Update the last flag
  if (tempLast) {

    // Do some black magic
    clearLast();

    // Did we overflow?
    if (gInboundWordPos > ETH_MTU_D4) {

      // Yup, we overflowed
      // This puts us back at the start, ready for a new one
      RESET_FRAME();
    }
    else {
      // No overflow condition, packet is good
      gCompletePacket = 1;
    }
  }
}

void sendFrame(u8 *frame, u32 byteSize) {

  u32 defaultWords;
  u32 finalWord = 0;
  u8 residue;
  
  defaultWords = (byteSize >> 2);
  residue = (u8)(byteSize - (defaultWords << 2));
  
  if(!residue) {
    --defaultWords;
    memcpy(&finalWord, frame + byteSize - 4, 4);
  }
  else
    memcpy(&finalWord, frame + byteSize - residue, residue);

  // Put all the default words
  // Recycle: byteSize
  u32 tmp = 0;
  while(tmp < defaultWords) {

    memcpy(&byteSize, frame + tmp * 4, 4);
    putfslx(byteSize, 0, FSL_DEFAULT);
    ++tmp;
  }

  // Now put the final word
  putfslx(finalWord, 0, FSL_CONTROL);
}

/// End Kurtis/Croker FSL routines


static int get_mac_address(u8 *mac) {

  u32 derp = 0;

  // mac is assumed to be a 6 byte wide array (ETH_ALEN)
  // Store this in big endian order!
  NISHI_REG_READ(derp, INTERNAL_OFFSET | REG_INTERNAL_DNA_LOW);
  derp = Xil_Htonl(derp);
  memcpy(mac+2, &derp, 4);

  NISHI_REG_READ(derp, INTERNAL_OFFSET | REG_INTERNAL_DNA_HIGH);
  derp = Xil_Htonl(derp);

  // derp is now big endian ordered, so the two LSB are at the 2 and 3 offset
  // note explicit cast to get the pointer arithmetic correct
  memcpy(mac, (u8 *)&derp+2, 2);

  // Kill multicast, so switches will route us.
  // This kills the least significant bit of the most significant byte, in network order
  // (MSB is [0], LSB is [ETH_ALEN])
  mac[0] &= 0xFE;

  return 0;
}

/*
 * Return checksum for the given data.
 * Copied from FreeBSD
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


/*
 * This function will be called for any incoming DHCP responses
 */
void dhcp_input(dhcp_t *dhcp) {

  u8 *ptr;
  u16 N;
  u8 scratch[6];
  
  // There could be something else making DHCP requests...
  // Do we care about offers?  Remember these were vectored directly at our MAC
  // and if we got this far (and we're on a switch) this was directed to us.
  if (! (dhcp->opcode == DHCP_OPTION_OFFER))
    return;

  if(!NIFT_ipsystem.configured) {
    
    // Immediately grab the IP address (this is set from the BOOTP and is not technically DHCP)
    NIFT_ipsystem.ip = Xil_Ntohl(dhcp->yiaddr);

    // Seems like my dhcp server is not setting the siaddr correctly in the BOOTP packet
    // extremely annoying.
    //    NIFT_ipsystem.dhcpserver = Xil_Ntohl(dhcp->siaddr);
  }

  // XXX: Assume that the DHCP-kine indicator is the first thing in the pocket...
  // Try to parse the messages to see what we are doing
  ptr = dhcp->bp_options;

  // Tag check
  if(*ptr != MESSAGE_TYPE_DHCP) {

    // Something is bzzz, deconfigure and try again
    NIFT_ipsystem.configured = 0;
    return;
  }

  // On the main tag.
  N = *(++ptr);
  ++ptr;

  // (This should be essentially += 2.)
  
  // Now we're on the main tag's data: OFFER, ACK, or NAK? 
  switch(*ptr) {

  case DHCP_OPTION_OFFER:
    // Okay, this was the server's offering.
    // Try to move into the confirmation phase

    // Because broken implementations of the server side
    // fail to set ciaddr correctly, I have to pull it out of the block of stupid

    while(NIFT_ipsystem.configured < 1) {

      // Skip the length of this block ahead.  Should be on next tag id.
      ptr += N;
      
      switch(*ptr) {

      case MESSAGE_TYPE_SELECTED_SERVER:
	// Advance to the length block (+1), then advance to the server block (+1)
	ptr += 2;
	//
	// Insane alignment behaviour again
	//	NIFT_ipsystem.dhcpserver = Xil_Ntohl(*(u32 *)ptr);
	//
	// TL;DR - If you try to dereference a memory location as a (u32 *) that
	//         does not sit on a 4 byte aligned address, uBlaze will freak out on you.
	//         But if you do it as a (u8 *) life is good
	//
	memcpy(&NIFT_ipsystem.dhcpserver, ptr, 4);
	NIFT_ipsystem.dhcpserver = Xil_Ntohl(NIFT_ipsystem.dhcpserver);
	NIFT_ipsystem.configured = 1;
	dhcp_request();
	break;

      case MESSAGE_TYPE_END:
	// Something was bzzzz 
	NIFT_ipsystem.configured = 0;
	break;
	
      default:
	// Skip this block
	N = *(++ptr);

	// Advance to the start of its data block so that we skip the correct number of bytes
	++ptr;
	break;
      }
    }
    return;

  case DHCP_OPTION_DECLINE:
  case DHCP_OPTION_NAK:
    // We were too slow on the draw
    // Restart the configuration process
    NIFT_ipsystem.configured = 0;
    return;

  case DHCP_OPTION_ACK:

    // Okay, this is the real deal guys.
    // We finally got our legit IP address.
    // We are a real human now.
    // We can  b r e e d.

    // Only need to parse this subset, because this is what we asked for.
    while(NIFT_ipsystem.configured < 2) {

      // We're on a message value, so advance to the next tag
      ptr += N;

      switch(*ptr) {
	
      case MESSAGE_TYPE_ROUTER:
	// Extract length field
	N = *(++ptr);

	// Advance to first router
	++ptr;
        memcpy(&NIFT_ipsystem.gateway, ptr, 4);
	NIFT_ipsystem.gateway = Xil_Ntohl(NIFT_ipsystem.gateway);
	break;

      case MESSAGE_TYPE_REQ_SUBNET_MASK:
	// Extract length
	N = *(++ptr);

	// Advance to the first subnet
	++ptr;
	memcpy(&NIFT_ipsystem.subnet_mask, ptr, 4);
	NIFT_ipsystem.subnet_mask = Xil_Ntohl(NIFT_ipsystem.subnet_mask);
	break;

      case MESSAGE_TYPE_END:

	// Okay, we're good.
	// Add the gateway machine to the arp cache
	arp_cache_resolve(NIFT_ipsystem.gateway, scratch);
		       
	NIFT_ipsystem.configured = 2;
	break;

      default:
	//
	// Was not advancing past bs options we don't care about.
	// No idea how this was triggering randomly or not....
	//
	N = *(++ptr);
	++ptr;
      }
    }
    break;
  default:
    // Its some field we don't know.
    // Pray to God that the fields are all treated as
    // dynamic in length, and that this is a length field.
    //
    // Explained:
    //  We are on a tag id block.
    //  ++ptr places on a length of following data block
    //  *(++ptr) extracts the length of the following data block
    //  ptr += *(++ptr) + 1  advances 1 to pass the length block and then N to pass the data
    N = *(++ptr);
    ++ptr;
    break;
  }
}

/*
 * UDP packet handler
 */
void udp_input(struct NIFT_source *source, struct udphdr * udp_packet) {

  if(NIFT_ipsystem.configured < 2) {
    
    // Only pay attention to DHCP packets if we are not configured
    if (Xil_Ntohs(udp_packet->uh_sport) == DHCP_SERVER_PORT)
      dhcp_input((dhcp_t *)((char *)udp_packet + sizeof(struct udphdr)));
    return;
  }

  // If the system is in manual, but not configured, bail (don't process UDP yet)
  if(NIFT_ipsystem.configured == 3)
    return;
  
  // We're configured.  Look for things we care about.  Things we need.
  if (Xil_Ntohs(udp_packet->uh_dport) == EEVEE_SERVER_PORT) {

    // XXX Before was not switching to host order. DIE
    // XXX This may now break because of insane microblaze alignment issues
    //
    // This includes the UDP header too, so subtract it off
    udp_packet->len = Xil_Ntohs(udp_packet->len) - sizeof(struct udphdr);

    // Basic sanity.  The 3 are the stop bytes
    if(udp_packet->len < sizeof(struct eevee))
      return;

    // Okay.  Attempt to parse.
    source->sport = Xil_Ntohs(udp_packet->uh_sport);
    eevee_input(source, (struct eevee *)((char *)udp_packet + sizeof(struct udphdr)), udp_packet->len);
    return;
  }
  
}

//
// Checks to make sure we won't WRITE past the boundary
//
void* safe_memcpy(void *dest, void *src, int N, void *boundary) {

  if(dest + N > boundary)
    return 0x0;

  return memcpy(dest, src, N);
}

//
// Checks to make sure we won't READ past a boundary
//
/* static void * sane_memcpy(void *dest, void *src, int N, void *boundary) { */

/*   if(src + N > boundary) */
/*     return 0x0; */

/*   return memcpy(dest, src, N); */
/* } */

//
// Handle OS side things for specific register writes
//
int os_handler(void) {

  // Six bytes of target hardware address
  u8 tha[6];
  u32 destip;
  
  // Check to see if the destination IP changed
  NISHI_REG_READ(destip, NBIC_OFFSET | REG_NBIC_DESTIP);

  // Hardware registers for the IP system are stored in BIG ENDIAN
  destip = Xil_Ntohl(destip);
    
  if(destip != NIFT_ipsystem.nbic_destip) {

    // We're setting the destination IP address for the NBIC
    // So we need to resolve this to a mac address

    // For REG_NBIC_DESTIP, tmp is supplied by the user (e.g. via python interface)
    // in NETWORK order because it is written to
    // the register in network order for convenience of the NBIC firmware.
    // To compare it against things we have, we need to switch it
    // tmp = Xil_Ntohl(tmp);

    // Update the cache (to detect future changes)
    NIFT_ipsystem.nbic_destip = destip;
    
    // Is it on our network?
    if( (NIFT_ipsystem.ip & NIFT_ipsystem.subnet_mask) == (destip & NIFT_ipsystem.subnet_mask) ) {

      // Attempt to resolve the ip address
      if(arp_cache_resolve(destip, tha)) {

	// We didn't resolve, so we've sent out an ARP request
	// We have to hit the main loop before any response gets processed
	// and added to the cache
	//
	// So this command needs to fail.
	return 1;
      }
    }
    else {

      // Its not on the network.
      // Attempt to resolve the gateway
      if(arp_cache_resolve(NIFT_ipsystem.gateway, tha)) {

	// This should not be failing, but be flexible...
	return 2;
      }
    }

    // If we've not returned yet, then we successfully resolved
    // (register writes expect little endian ordered bytes)
    // (because register reads expect little endian ordered bytes)
    memcpy(&destip, tha + 2, 4);
    destip = Xil_Ntohl(destip);
    NISHI_REG_WRITE(NBIC_OFFSET | REG_NBIC_DESTMAC_LOW, destip);
    destip = 0;
    memcpy((u8 *)&destip + 2, tha, 2);
    destip = Xil_Ntohl(destip);
    NISHI_REG_WRITE(NBIC_OFFSET | REG_NBIC_DESTMAC_HIGH, destip);     
  }

  // Success.
  return 0;
}

// Cannot be accessed by modules enforced at compile time!
#ifdef STATIC_PACKET_BUFFER
static u8 outPacket[ETH_MTU + ETH_PAYLOAD_ALIGNMENT_SHIFT];
#endif

// Wrappers for static backing of packet
// This is not re-entrant, so packets WILL get overwritten
u8 *mallocPacket(u16 size) {

  // If they ask for too much, bail
  if(size > ETH_MTU)
    return NULL;
      
#ifdef STATIC_PACKET_BUFFER

  // Don't waste time resetting stuff we don't need
  memset(outPacket, 0, size + ETH_PAYLOAD_ALIGNMENT_SHIFT);
  return outPacket + ETH_PAYLOAD_ALIGNMENT_SHIFT;

#else

  u8 *packet;

  if(! (packet = memalign(4, size + ETH_PAYLOAD_ALIGNMENT_SHIFT)))
    return NULL;

  memset(packet, 0, size);
  packet += ETH_PAYLOAD_ALIGNMENT_SHIFT;
  return packet;

#endif
}

int transmitPacket(u8 *packet, u16 src_port, u32 dest_ip, u16 dest_port, int unwrapped_length) {

  u8 dest_mac[ETH_ALEN];
  struct ip *ip_header;
  struct udphdr *udp_header;

  ip_header = (struct ip *)DISPLACE(packet, struct ether_header);
  udp_header = (struct udphdr *)DISPLACE(ip_header, struct ip);
  
  // Scribble the headers in place
  udp_output(udp_header, src_port, dest_port, &unwrapped_length);
  ip_output(ip_header, dest_ip, IPPROTO_UDP, &unwrapped_length);

  // For the final one, transmit.
  // I should be able to do an arp resolve...
  if(!arp_cache_resolve(dest_ip, dest_mac)) {

    ether_output(packet, dest_mac, ETHERTYPE_IP, unwrapped_length);
    return 0;
  }
  else
    return unwrapped_length + sizeof(struct ether_header);
}

void freePacket(u8 *packet) {

#ifdef STATIC_PACKET_BUFFER
  return;
#else
  free(packet - ETH_PAYLOAD_ALIGNMENT_SHIFT);
#endif
  
}
			   
void eevee_input(struct NIFT_source *source, struct eevee *eeveehdr_in, int transaction_len) {

  //u32 tmp, reg;
  u8 *boundary, *read_boundary;
  u16 op, N;
  u8 *packet;
  u16 width;
  u8 respond;
  int len;

#ifdef EEVEE_STONES
  int r;
#endif
  
  struct ip *ip_header;
  struct udphdr *udp_header;
  struct eevee *eeveehdr_out;
  struct eevee_payload *payloadhdr_in, *payloadhdr_out;
  struct eevee_register *regptr;

#ifdef EEVEE_STONES
  struct eevee_stone *stone;
#endif
  
  // Verify that the magic is right
  if(Xil_Ntohl(eeveehdr_in->magic) != EEVEE_MAGIC_COOKIE)
    return;

  // Okay, we're probably going to send something back.
  // So start building a packet.
  // But even so, start in silent mode.
  respond = 0;
  
  // Do only 512 bytes for now.
  packet = mallocPacket(ETH_MTU);
  ip_header = (struct ip *)DISPLACE(packet, struct ether_header);
  udp_header = (struct udphdr *)DISPLACE(ip_header, struct ip);
  eeveehdr_out = (struct eevee *)DISPLACE(udp_header, struct udphdr);
  payloadhdr_out = (struct eevee_payload *)DISPLACE(eeveehdr_out, struct eevee);
      
  // Initialize it
  eeveehdr_out->magic = Xil_Htonl(EEVEE_MAGIC_COOKIE);
  eeveehdr_out->version = Xil_Htonl(eevee.version);

  // Increment the sequence number in the response
  // Since Xil endian swaps are actual function calls, can use the
  // same variable in the call as the assign...
  eeveehdr_out->seqnum = Xil_Ntohl(eeveehdr_in->seqnum) + 1;
  eeveehdr_out->seqnum = Xil_Htonl(eeveehdr_out->seqnum);

  // Establish an incoming buffer boundary, so we don't overrun and read UTTER INSANITY
  // (Notice the cast to make sure we do ptr arithmetic correctly)
  read_boundary = (u8 *)eeveehdr_in->transaction + transaction_len - sizeof(struct eevee);

  // Establish the outgoing buffer boundary, so we don't overwrite and corrupt
  boundary = packet + ETH_MTU;

  // Set the number of output bytes to write
  len = 0;
  
  // Set ptr to payload base
  payloadhdr_in = eeveehdr_in->transaction;

  // If the version check fails, respond with our version
  if(Xil_Ntohl(eeveehdr_in->version) != eevee.version)
    respond = 1;
  else {

    // Loop over all the transactions
    while((u8 *)payloadhdr_in < read_boundary) {
      
      // Get the operation and width
      op = Xil_Ntohs(payloadhdr_in->op);
      width = Xil_Ntohs(payloadhdr_in->width);
      
      // Is it a register operation?
      if( (op & EEVEE_OP_REGISTER) && !(op & EEVEE_OP_OTHER)) {
	// If reading all registers would overflow, bail
	if(payloadhdr_in->payload + width > read_boundary) {

	  freePacket(packet);
	  return;
	}
      
	// If the width is not an integer multiple of a register pair, bail
	if(width % sizeof(struct eevee_register)) {

	  freePacket(packet);
	  return;
	}

	// Integer division to get the number of register operations
	N = width / sizeof(struct eevee_register);
	
	// Perform writes?
	if( op & EEVEE_WRITE ) {
      
	  // Iterate through the register operations
	  for(regptr = (struct eevee_register *) (payloadhdr_in->payload); N > 0; --N, ++regptr)
	    NISHI_REG_WRITE(regptr->addr, regptr->word);
	}

	// Did we write and ask for a response OR are we reading?
	if(!(op & EEVEE_OP_MASK_SILENT) || (op & EEVEE_READ) ) {

	  // Flag a response
	  respond = 1;
	  
	  // Reset N
	  N = width / sizeof(struct eevee_register);

	  // If we cannot copy over the this register transaction, bail
	  if(!safe_memcpy(payloadhdr_out, payloadhdr_in, sizeof(struct eevee_payload) + width, boundary)) {
	    
	    freePacket(packet);
	    return;
	  }

	  // Increment the number of output bytes to write
	  len += sizeof(struct eevee_payload) + width;
	  
	  // Iterate through again and read out the registers
	  // and "erase and fill in the blanks"
	  // Only do this if we want readback!
	  if(!(op & EEVEE_OP_MASK_NOREADBACK)) {
	    
	    for(regptr = (struct eevee_register *) (payloadhdr_out->payload); N > 0; --N, ++regptr)
	      NISHI_REG_READ(regptr->word, regptr->addr);
	  }
	  
	  // Since we did a write, advance the outgoing block too
	  payloadhdr_out = (struct eevee_payload *) ( (u8 *)payloadhdr_out + sizeof(struct eevee_payload) + width);
	}
      }
#ifdef EEVEE_STONES
      else if( (op & EEVEE_OP_OTHER) && !(op & EEVEE_OP_REGISTER) ) {


	//
	// Iterate over all extensions
	// Stone handlers return:
	//   -1   if they chose to not service
	//   0    if they serviced correctly
	//   > 0  if there was some sort of error
	//
	stone = eevee.stones;
	r = -1;
	while(stone && r) {

	  // Call all non-null handlers
	  if(stone->handler != NULL)
	    r = stone->handler(payloadhdr_in, stone->bp);

	  stone = stone->next;
	}

	// We successfully handled a payload
	if(!r) {

	  // Should we respond?
	  if(!(op & EEVEE_OP_MASK_SILENT)) {

	    respond = 1;
	    
	    // If we cannot copy over the this register transaction, bail
	    if(!safe_memcpy(payloadhdr_out, payloadhdr_in, sizeof(struct eevee_payload) + width, boundary)) {
	    
	      freePacket(packet);
	      return;
	    }

	    // Increment the number of output bytes to write
	    len += sizeof(struct eevee_payload) + width;
	  }
	}
      }
#endif
      else {

	// An invalid request, bail
	freePacket(packet);
	return;
      }

      // Now advance to the next item in the transactions
      payloadhdr_in = (struct eevee_payload *) ( (u8 *)payloadhdr_in + sizeof(struct eevee_payload) + width );

    }
  }
  
  // If we want the response (so at least one command was not silenced)
  // send it out.
  if(respond) {
      
    // We've completed our serialized list.
    // Increment len once more to capture the header length
    //
    // XXX is this a buffer overrun too?
    len += sizeof(struct eevee);
    
    // Send our response
    // Don't like how we pass the actual value in ether_output
    // ... breaks with the other semantics
    //udp_output(udp_header, EEVEE_SERVER_PORT, source->sport, &len);
    //ip_output(ip_header, source->sip.s_addr, IPPROTO_UDP, &len);
    //ether_output(packet, source->smacn, ETHERTYPE_IP, len);
    transmitPacket(packet, EEVEE_SERVER_PORT, source->sip.s_addr, source->sport, len);
  }

  // Run os updating checks (on changed registers)
  os_handler();
  
  // Clean up
  freePacket(packet);
}

/*
 * IP Packet handler
 */
void ip_input(struct NIFT_source *source, struct ip * ip_packet) {

  // This seems pretty generic for IP packets...
  source->sip.s_addr = Xil_Ntohl(ip_packet->ip_src.s_addr);

  // Do I need to fix the length to host order?
  ip_packet->ip_len = Xil_Ntohs(ip_packet->ip_len);

  // Is it on my subnet?
  // If so, I probably want to keep talking to it 
  if( (NIFT_ipsystem.ip & NIFT_ipsystem.subnet_mask) == (source->sip.s_addr & NIFT_ipsystem.subnet_mask))
    arp_cache_push(source->sip.s_addr, source->smacn);
  
  // We push to protocol processing the data minus the ip header
  if (ip_packet->ip_p == IPPROTO_UDP)
    udp_input(source, (struct udphdr *)((char *)ip_packet + sizeof(struct ip)));
  else if(ip_packet->ip_p == IPPROTO_ICMP)
    icmp_input(source, (struct icmphdr *)((char *)ip_packet + sizeof(struct ip)), ip_packet);
}

/*
 * Ethernet output handler - Fills appropriate bytes in ethernet header
 */
void ether_output(u8 *frame, u8 *dmacn, short ethertype, int len) {

    struct ether_header *eframe = (struct ether_header *)frame;

    // Note that this is only for DHCP, since we are broadcasting (-1 rolls over)
    memcpy(eframe->ether_shost, NIFT_ipsystem.mac, ETHER_ADDR_LEN);
    memcpy(eframe->ether_dhost, dmacn,  ETHER_ADDR_LEN);
    eframe->ether_type = Xil_Htons(ethertype);

    len = len + sizeof(struct ether_header);

    sendFrame(frame, len);
}

//
// Originally from ethPackets.c
// by Kurtis Nishimura
//
u16 calcIcmpChecksum(char *data, int nPayloadBytes) {
   u16 *dataAddr = ( u16 *) data;
   int i;
   
  u32 checksum = 0;
  for (i = 0; i < nPayloadBytes/2; ++i) {
    checksum += Xil_Ntohs(dataAddr[i]);
	}
  while (checksum & 0xFFFF0000) {
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
  }
  checksum = ~checksum;
  return (u16) checksum;
}

void icmp_input(struct NIFT_source *source, struct icmphdr *icmp_packet, struct ip *ip_packet) {

  u8 *packet;
  u8 *boundary;
  struct ip *ip_header;
  struct icmphdr *icmp_header;

  // OOO all int lengths should really be u16, because there are no negative lengths!
  int len;
  
  // Only respond to echo requests
  if(icmp_packet->type == ICMP_ECHO) {

    // If we're not IP configured, we don't know how to echo...
    if(NIFT_ipsystem.configured < 2) {
      return;
    }
    
    // ICMP echo reply should be the same size as the echo request
    // Construct an echo packet
    packet = mallocPacket(sizeof(struct ether_header) + ip_packet->ip_len);
    if(!packet)
      return;

    // Set up a little cage
    boundary = packet + sizeof(struct ether_header) + ip_packet->ip_len; 
    
    // Index into the packet
    ip_header = (struct ip *)DISPLACE(packet, struct ether_header);
    icmp_header = (struct icmphdr *)DISPLACE(ip_header, struct ip);

    // Echo copies the packet exactly...
    if(!safe_memcpy(icmp_header, icmp_packet, ip_packet->ip_len - sizeof(struct ip), boundary)) {

      // This was a memory leak!
      freePacket(packet);
      return;
    }
    
    // ... but switches a few things in the header
    icmp_header->type = ICMP_ECHOREPLY;
    icmp_header->code = 0;
    icmp_header->checksum = 0x0;
    
    // Compute the checksum
    // via Kurtis function
    icmp_header->checksum = Xil_Htons(calcIcmpChecksum((char *)icmp_header, ip_packet->ip_len - sizeof(struct ip)));

    len = ip_packet->ip_len - sizeof(struct ip);
    
    // Output a response
    ip_output(ip_header, source->sip.s_addr, IPPROTO_ICMP, &len);
    ether_output(packet, source->smacn, ETHERTYPE_IP, len);

    // Cleanup
    freePacket(packet);
  }
}

 void arp_cache_push(u32 ip, u8 *mac) {

   u8 i;

   // If its already here, bail.
   for(i = 0; i < ARP_TABLE_LEN; ++i) {
     if(NIFT_ipsystem.arpTable[i].ipaddr_n.s_addr == ip)
       return;
   }

   // Stick it in.
   NIFT_ipsystem.arpTable[NIFT_ipsystem.arpTableNext].ipaddr_n.s_addr = ip;
   memcpy(&NIFT_ipsystem.arpTable[NIFT_ipsystem.arpTableNext].mac_n, mac, 6);

   // NOTICE: the increment, which I do inside the check!!!
   //         (We we are full, start overwriting from the top)
   if(++NIFT_ipsystem.arpTableNext >= ARP_TABLE_LEN)
     NIFT_ipsystem.arpTableNext = 0;
 }

 int arp_cache_resolve(u32 ip, u8 *mac) {

   // Search all entries
   // (Be clever later)
   u8 i;
   u8 *packet;
   struct arphdr *arp_packet;

   // Is it in the cache?
   for(i = 0; i < ARP_TABLE_LEN; ++i) {
     if(NIFT_ipsystem.arpTable[i].ipaddr_n.s_addr == ip) {
       memcpy(mac, NIFT_ipsystem.arpTable[i].mac_n, 6);
       return 0;
     }
   }

   // We didn't find it, so send an arp request
   packet = mallocPacket(sizeof(struct ether_header) + sizeof(struct arphdr));
   if(!packet) {
     errno = ENOMEM;
     return 3;
   }
   arp_packet = (struct arphdr *)DISPLACE(packet, struct ether_header);

   // Remind me again why I store IP address in host order
   // by macs in network order? ...
   memset(arp_packet->ar_tha, 255, 6);
   memcpy(arp_packet->ar_sha, &NIFT_ipsystem.mac, 6);

   arp_packet->ar_hrd = Xil_Htons(ARPHRD_ETHER);
   arp_packet->ar_pro = Xil_Htons(ETHERTYPE_IP);
   arp_packet->ar_hln = ETHER_ADDR_LEN;
   arp_packet->ar_pln = 4;
   arp_packet->ar_op = Xil_Htons(ARPOP_REQUEST);

   //
   // Recycle: ip
   //
   ip = Xil_Htonl(ip);
   memcpy(arp_packet->ar_tip, &ip, 4);

   ip = Xil_Htonl(NIFT_ipsystem.ip);
   memcpy(arp_packet->ar_sip, &ip, 4);
      
   ip = sizeof(struct arphdr);
   ether_output(packet, arp_packet->ar_tha, ETHERTYPE_ARP, ip);
   freePacket(packet);
   
   return 1;
 }
 
 void arp_input(struct arphdr *arp_packet) {

  u32 tmp;
  u8 *packet;

  // Don't bail yet.
  // We can use this as a hackish IP assignment technique...
  
  // Is it Ethernet arp?
  // This is a multibytye value
  if(arp_packet->ar_hrd != Xil_Htons(ARPHRD_ETHER))
    return;

  // Is it the ethernet protocol?
  if(arp_packet->ar_pro != Xil_Htons(ETHERTYPE_IP))
    return;

  // Does it have the right length?
  if(arp_packet->ar_hln != ETHER_ADDR_LEN)
    return;

  // Is the length of the protocol address correct for IP (since we are looking at ETHERTYPE_IP)
  // and v4 IP addresses are 4 bytes
  if(arp_packet->ar_pln != 4)
    return;

  // Are we asking for or receiving ARP information?
  if(arp_packet->ar_op == Xil_Htons(ARPOP_REPLY)) {

    if(NIFT_ipsystem.configured == 2 || NIFT_ipsystem.configured == 4)  {

      // Was this arp response intended for us?
      tmp = Xil_Htonl(NIFT_ipsystem.ip);
      if(memcmp(arp_packet->ar_tip, &tmp, 4))
	return;

      // It was!  Add it to the cache
      memcpy(&tmp, arp_packet->ar_sip, 4);
      tmp = Xil_Ntohl(tmp);
      arp_cache_push(tmp, arp_packet->ar_sha);

      // Are we in manual mode and did we get a response from "ourselves"?
      if (NIFT_ipsystem.configured == 4 && tmp == NIFT_ipsystem.ip) {
	
	// We sent out a request to see if anyone else had this IP
	// and it seems like someone else does.
	//
	// We have cached this address, so we won't try to seize it again.
	  
	// Deconfigure the system and return to manual mode
	NIFT_ipsystem.subnet_mask = 0x0;
	NIFT_ipsystem.ip = 0x0;
	NIFT_ipsystem.gateway = 0x0;
	NIFT_ipsystem.configured = 3;
	NISHI_REG_WRITE(EEVEE_OFFSET | REG_EEVEE_SRCIP, Xil_Htonl(NIFT_ipsystem.ip));
      }
    }
    return;
  }
  else if(arp_packet->ar_op == Xil_Htons(ARPOP_REQUEST)) {

    if(NIFT_ipsystem.configured == 2 || NIFT_ipsystem.configured == 4) {
      
      // Are they looking for us?  (We're going to want our IP address in network order if it is)
      tmp = Xil_Htonl(NIFT_ipsystem.ip);
      if(memcmp(arp_packet->ar_tip, &tmp, 4))
	return;

      // Cache these anyway, since we will probably be talking to this person
      memcpy(&tmp, arp_packet->ar_sip, 4);
      arp_cache_push(Xil_Ntohl(tmp), arp_packet->ar_sha);
    
      // Construct an arp response by just modifying the entries in this packet and
      // sending it back out
      arp_packet->ar_op = Xil_Htons(ARPOP_REPLY);
      memcpy(arp_packet->ar_tha, arp_packet->ar_sha, ETH_ALEN);
      memcpy(arp_packet->ar_sha, &NIFT_ipsystem.mac, ETH_ALEN);
      memcpy(arp_packet->ar_sip, arp_packet->ar_tip, 4);
      memcpy(arp_packet->ar_tip, &tmp, 4);

      // Meh.  Let's not be shady.  Make a new packet, and populate it reasonably
      packet = mallocPacket(sizeof(struct ether_header) + sizeof(struct arphdr));
      if(!packet) {
	errno = ENOMEM;
	return;
      }
  
      //
      // Recycle: tmp
      //   Was: our ip address in network byte order
      //   Is:  The length of our packet
      //
      tmp = sizeof(struct arphdr);
      memcpy(packet + sizeof(struct ether_header), arp_packet, tmp);
      ether_output(packet, arp_packet->ar_tha, ETHERTYPE_ARP, tmp);
      freePacket(packet);
    }
    else if(NIFT_ipsystem.configured == 3) {

      // Okay, we are at the first stage of a manual assignment
      // 1) We will stash this target IP address as ours,
      // 2) We will stash this source IP as the gateway
      // 3) We will assume a private 255.255.255.0 subnet
      // 4) We will send our own arp request for this IP.
      //
      // If it is answered, we fall-back to level 3 and reset the stashes
      //
      // If it is not (...), we seize it
      //
      memcpy(&NIFT_ipsystem.ip, arp_packet->ar_tip, 4);
      NIFT_ipsystem.ip = Xil_Ntohl(NIFT_ipsystem.ip);
     
      // Have we tried this before?  Send outgoing arp to see if someone already has this
      if(!arp_cache_resolve(NIFT_ipsystem.ip, arp_packet->ar_tha)) {

	// We already tried unsuccessfully to seize this address, release it
	NIFT_ipsystem.ip = 0x0;
	return;
      }

      // No one has previously responded to this...
      NIFT_ipsystem.subnet_mask = 0xffffff00;
      memcpy(&NIFT_ipsystem.gateway, arp_packet->ar_sip, 4);
      NIFT_ipsystem.gateway = Xil_Ntohl(NIFT_ipsystem.gateway);
      NISHI_REG_WRITE(EEVEE_OFFSET | REG_EEVEE_SRCIP, Xil_Htonl(NIFT_ipsystem.ip));

      // Move to configuration level 4
      NIFT_ipsystem.configured = 4;
    }
  }
}

/*
 * Ethernet packet handler
 */
void ether_input(const u8 *frame) {

  // We cast as ether header, so that we can offset into the first bytes.
  struct ether_header *eframe = (struct ether_header *)frame;
  ushort ethertype;

  // Gross hacks.
  struct NIFT_source source;
    
  ethertype = Xil_Ntohs(eframe->ether_type);

  // Uhh, is it for our MAC address or the broadcast?
  // Comment this out if you want to operate promiscously...
  if(memcmp(eframe->ether_dhost, NIFT_ipsystem.mac, ETH_ALEN)) {
    if(memcmp(eframe->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETH_ALEN))
      return;
  }
    
  switch(ethertype) {
    
  case ETHERTYPE_IP:
    memcpy(&source.smacn, eframe->ether_shost, ETH_ALEN);
    ip_input(&source, (struct ip *)(frame + sizeof(struct ether_header)));
    break;
  case ETHERTYPE_ARP:
    arp_input((struct arphdr *)(frame + sizeof(struct ether_header)));
    break;
  default:
    break; 
  }
}

// This can now be used to wrap arbitrary IP packets heading to dst. 
void ip_output(struct ip *ip_header, u32 dst, int proto, int *len) {
  
    *len += sizeof(struct ip);

    ip_header->ip_hl = 5;
    ip_header->ip_v = 4; //IPVERSION;
    ip_header->ip_tos = 0x10;
    ip_header->ip_len = Xil_Htons(*len);
    ip_header->ip_id = Xil_Htons(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = proto; //IPPROTO_UDP;
    ip_header->ip_sum = 0;

    // If we're not yet configured, send from the aether
    // XXX MANUAL needs adjustment
    // By default, the ip is set to 0x0 anyway, so this doesn't change anything
    if(NIFT_ipsystem.configured == 2 || NIFT_ipsystem.configured == 4)
      ip_header->ip_src.s_addr = Xil_Htonl(NIFT_ipsystem.ip);
    else
      ip_header->ip_src.s_addr = 0x0;
   
    // Set the destination
    ip_header->ip_dst.s_addr = Xil_Htonl(dst);
    
    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));
}

/*
 * UDP output - Fills appropriate bytes in UDP header
 */
void udp_output(struct udphdr *udp_header, u16 sport, u16 dport, int *len) {

  // KC 10/22/18
  // ??? What's this doing?
  if (*len & 1)
    *len += 1;
  *len += sizeof(struct udphdr);
  
  udp_header->uh_sport = Xil_Htons(sport);
  udp_header->uh_dport = Xil_Htons(dport);
  udp_header->uh_ulen = Xil_Htons(*len);
  udp_header->uh_sum = 0;
}

void dhcp_output(dhcp_t *dhcp, u_int8_t *mac, int *len)
{
    *len += sizeof(dhcp_t);
    memset(dhcp, 0, sizeof(dhcp_t));

    // This is the same for the DISCOVER and REQUEST
    dhcp->opcode = DHCP_BOOTREQUEST;
    dhcp->htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp->hlen = 6;
    memcpy(dhcp->chaddr, mac, DHCP_CHADDR_LEN);

    dhcp->magic_cookie = Xil_Htonl(DHCP_MAGIC_COOKIE);
}

/*
 * Adds DHCP option to the bytestream
 */
int fill_dhcp_option(u_int8_t *packet, u_int8_t code, u_int8_t *data, u_int8_t len)
{
    packet[0] = code;
    packet[1] = len;
    memcpy(&packet[2], data, len);

    return len + (sizeof(u_int8_t) * 2);
}

/*
 * Fill DHCP options
 */
int fill_dhcp_discovery_options(dhcp_t *dhcp) {
  
  int len = 0;
  u32 req_ip;
  u8 parameter_req_list[] = {MESSAGE_TYPE_REQ_SUBNET_MASK, MESSAGE_TYPE_ROUTER};
  u8 option;

  option = DHCP_OPTION_DISCOVER;
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP, &option, sizeof(option));
  req_ip = Xil_Htonl(0xc0a8010a);
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_REQ_IP, (u8 *)&req_ip, sizeof(req_ip));
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_PARAMETER_REQ_LIST, (u8 *)&parameter_req_list, sizeof(parameter_req_list));
  option = 0;
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_END, &option, sizeof(option));

  return len;
}

int fill_dhcp_request_options(dhcp_t *dhcp) {

  int len = 0;
  u8 option;
  u32 buf;
  
  // Set up 53: 3
  option = DHCP_OPTION_REQUEST;
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP, &option, sizeof(option));

  // Set up 50
  buf = Xil_Htonl(NIFT_ipsystem.ip);
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_REQ_IP, (u8 *)&buf, sizeof(buf));

  // Set up 54
  buf = Xil_Htonl(NIFT_ipsystem.dhcpserver);
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_SELECTED_SERVER, (u8 *)&buf, sizeof(buf));

  // Close the options block
  option = 0; 
  len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_END, &option, sizeof(option));

  return len;
}

int dhcp_request(void) {
  
  int len = 0;
  u8 *packet;
  struct udphdr *udp_header;
  struct ip *ip_header;
  dhcp_t *dhcp;
  u8 buf[ETH_ALEN];
  
  packet = mallocPacket(512);
  if(!packet)
    return 1;
    
  // Index into the packet cleverly!
  ip_header = (struct ip *)DISPLACE(packet, struct ether_header);
  udp_header = (struct udphdr *)DISPLACE(ip_header, struct ip);
  dhcp = (dhcp_t *)DISPLACE(udp_header, struct udphdr);
 
  // Populate DHCP payload
  len = fill_dhcp_request_options(dhcp);
  dhcp_output(dhcp, NIFT_ipsystem.mac, &len);

  // Populate udp header
  udp_output(udp_header, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &len);

  // Populate IP headcer
  ip_output(ip_header, 0xffffffff, IPPROTO_UDP, &len);

  // Populate ethernet header and ship
  memset(buf, -1, ETH_ALEN);
  ether_output(packet, buf, ETHERTYPE_IP, len);

  // Clean up
  freePacket(packet);
  return 0;
}

/*
 * Send DHCP DISCOVERY packet
 */
    		
int dhcp_discovery(void) {

  int len = 0;

  u8 *packet;
  struct udphdr *udp_header;
  struct ip *ip_header;
  dhcp_t *dhcp;
  u8 buf[ETH_ALEN];
  
  packet = mallocPacket(512);
  if(!packet)
    return 1;
    
  // Index into the packet cleverly!
  ip_header = (struct ip *)DISPLACE(packet, struct ether_header);
  udp_header = (struct udphdr *)DISPLACE(ip_header, struct ip);
  dhcp = (dhcp_t *)DISPLACE(udp_header, struct udphdr);
 
  // Populate DHCP payload
  len = fill_dhcp_discovery_options(dhcp);
  dhcp_output(dhcp, NIFT_ipsystem.mac, &len);

  // Populate udp header
  udp_output(udp_header, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &len);

  // Populate IP header
  ip_output(ip_header, 0xffffffff, IPPROTO_UDP, &len);

  // Populate ethernet header and ship
  memset(buf, -1, ETH_ALEN);
  ether_output(packet, buf, ETHERTYPE_IP, len);

  // Clean up
  freePacket(packet);
  return 0;
}

int main(void) {
  
  u32 result;
  int k;
#ifdef EEVEE_STONES
  struct eevee_stone *stone;
#endif
  
  // Fetch the *firmware* version of this board
  NISHI_REG_READ(result, INTERNAL_OFFSET | REG_INTERNAL_VERSION);

  // We take the low 4 bytes of this internal version, and make them the high 4 bytes
  // of the version
  eevee.version = result << 16;

  // And then OR in the the software version as the low 4 bytes 
  eevee.version |= (EEVEE_VERSION_MASK_SOFT & EEVEE_VERSION_SOFT);
  
  // Set up cache for incoming ethernet frames
  // Use static allocation for this.  Stupid shenegains
  //  initMemory();
  // gInboundData = (u8 *) memalign(4, ETH_MTU + ETH_PAYLOAD_ALIGNMENT_
  // if(!gInboundData)
  //  exit(2);
  
  // KC 9/13/18 - why are we advancing 2 pointer widths?
  // A: Because the ethernet PAYLOAD must sit on a 4-byte aligned boundary
  //    or else everything else is bzzzz 
  //
  gInboundData = gInboundData_buffer + ETH_PAYLOAD_ALIGNMENT_SHIFT;
  gInboundFrame = (struct EthFrame *) gInboundData;

  // Do clear it once
  memset(gInboundData_buffer, 0, ETH_MTU);
  
  RESET_FRAME();

  
  /* Get the MAC address of the interface */
  result = get_mac_address(NIFT_ipsystem.mac);
    
  // If this doesn't work, something is badly broken with the IOmodule.
  // Just die.
  if (result)
    return 1; 

  // Set the mac address.
  // Recycle: result, which must be zero.
  // (Not redundant, since not all Xilinx platforms have a device DNA.)
  // Since register reads and writes are dereferences, we need this to be in little endian
  memcpy(&result, NIFT_ipsystem.mac + 2, 4);
  result = Xil_Ntohl(result);
  NISHI_REG_WRITE(EEVEE_OFFSET | REG_EEVEE_SRCMAC_LOW, result);
  result = 0;
  memcpy((u8*)&result + 2, NIFT_ipsystem.mac, 2);
  result = Xil_Ntohl(result);
  NISHI_REG_WRITE(EEVEE_OFFSET | REG_EEVEE_SRCMAC_HIGH, result);

  // Initialize an empty arp table
  NIFT_ipsystem.arpTableNext = 0;

  // Set the dest_ip to bullshit (that the router won't drop...)
  NIFT_ipsystem.nbic_destip = 0;
  
  // Get on the intarwebs
  result = 5;
  while(result) {

    // Send DHCP DISCOVERY packet
    if(!NIFT_ipsystem.configured) {

      // This only errors out if it cannot allocate memory
      // which means something is broken in the linker configuration.
      if(dhcp_discovery())
	return 1;
    }
      
    // First take in 1 frame, then 2, then ..., then 9
    k = 5 - (--result);
    
    while(NIFT_ipsystem.configured < 2 && k-- > 0) {

      while(!gCompletePacket)
	readFsl();

      ether_input(gInboundData);
      RESET_FRAME();
    }
      
    // If we completed, write it and break
    if(NIFT_ipsystem.configured == 2) {
      // Ip system is configured.  Set the values into the registers
      NISHI_REG_WRITE(EEVEE_OFFSET | REG_EEVEE_SRCIP, Xil_Htonl(NIFT_ipsystem.ip));
      break;
    }
  }

  // Did we complete?
  if(!result) {

    // Enter manual configuration mode
    NIFT_ipsystem.configured = 3;
  }

#ifdef EEVEE_STONES
  // Initialize the extension stuff
  eevee.stones = NULL;

  // Add the telemetry stone
#ifdef TELEMETRY_STONE
  registerStone("telemetry", telemetryHook, telemetryHandler);
#endif

#endif
  
  // We escaped the configuration loop, so we're online.
  while(1) {

#ifdef EEVEE_STONES
    // Iterate over all extensions first.
    // This is because extension hooks are responsible
    // for initialization, and so handlers might not work
    // until initialization.
    stone = eevee.stones;
    while(stone) {

      // ... call the hooks
      stone->hook(NULL, stone->bp);
      stone = stone->next;
    }
#endif
    
    // Take in some bytes from the SFP
    readFsl();

    // If we have an entire packet, process it
    if(gCompletePacket) {
      ether_input(gInboundData);
      RESET_FRAME();
    }      
  }
  
  // Clean up the frame
  // free(gInboundData - 2);
}
