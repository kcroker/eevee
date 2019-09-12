/////// STONE COMMON ENTRY /////////////////////////////////////

#include "platform_definition.h"
#ifdef EEVEE_STONES

#include "xil_types.h"
#include "xil_io.h"
#include <unistd.h>

#define STONE
#include "eevee_stones.h"

// The content of the lines below should be changed
// to identify your stone

#ifdef TELEMETRY_STONE
#include "eevee_telemetry_stone.h"

/////// THE **ORDER** OF THE ABOVE LINES CANNOT BE CHANGED //////

#include "eevee_regmap.h"
#include "eevee_control.h"

//
// External things from eevee_os.c
// You should really only use these things!
//
extern struct NIFT_ip NIFT_ipsystem;

struct telemetry_stone *telemetryInit(void **bp) {

  struct telemetry_stone *state;

  // Store the location of the allocated memory at this place inside the structure
  (*bp) = stoneMalloc(sizeof(struct telemetry_stone), telemetryHook);
  if( (*bp) == NULL )
    return NULL;

  // Convenience cast
  state = (struct telemetry_stone *)(*bp);

  // Module specific initialization
  state->previousClock = 0;
  state->registers = NULL;
  state->Nreg = 0;
  state->fired = 0;
  return state;
}

int telemetryHandler(struct eevee_payload *payload, void **bp) {

  // We have an incoming telemetry request
  struct telemetry_stone *state;
  struct telemetry_header *indata;
  u16 regwidth;
  u16 n;
  
  // We are presented the raw payload
  // so things are still in network order!

  // First, see if we should care about this payload?
  if( (Xil_Ntohs(payload->op) >> EEVEE_OP_SHIFT) != TELEMETRY_OFFSET)
    return -1;
     
  // Convenience casts and math
  state = (struct telemetry_stone *)(*bp);
  indata = (struct telemetry_header *)payload->payload;
  regwidth = Xil_Ntohs(payload->width) - sizeof(struct telemetry_header);
  
  // Sanity check: is width sane?
  if(regwidth % sizeof(struct eevee_register))
    return 1;

  // Set the number of registers
  state->Nreg = regwidth / sizeof(struct eevee_register);
  
  // Set values for new telemetry
  memcpy(&(state->header), indata, sizeof(struct telemetry_header));

  // Flip the byte orders (gross)
  state->header.address.dest.ip = Xil_Ntohl(state->header.address.dest.ip);
  state->header.address.dest.port = Xil_Ntohs(state->header.address.dest.port);
  state->header.timestamp.words.low = Xil_Ntohl(state->header.timestamp.words.low);

  // Free the previous list if its there
  if(state->registers)
    stoneFree(state->registers, telemetryHook);

  // Sanity check the delay and bail at this point if its 0
  // Set state->registers=NULL, which means to leave the hook immediately
  if(!state->header.timestamp.words.low) {

    state->registers = NULL;
    return 2;
  }
  // Allocate the register list
  if(! (state->registers = (struct eevee_register *)stoneMalloc(regwidth, telemetryHook)))
    return 3;

  // (Notice failure resets it to NULL, so we remain well-defined here)
  
  // Copy over the requested registers
  memcpy(state->registers, indata->registers, regwidth);

  // Stuper stupid if I have to endian flip them...
  for(n = 0; n < state->Nreg ; ++n)
    state->registers[n].addr = Xil_Ntohl(state->registers[n].addr);
  
  // Set the previous clock to now
  NISHI_REG_READ(state->previousClock, EEVEE_OFFSET | REG_EEVEE_CLOCK);

  // STATE CACHE COMPLETE.

  // Munge the payload so that it contains the mac address and current ticks
  memcpy(indata->address.mac, NIFT_ipsystem.mac, ETH_ALEN);
  NISHI_REG_READ(indata->timestamp.words.low, EEVEE_OFFSET | REG_EEVEE_TICKS_LOW);
  NISHI_REG_READ(indata->timestamp.words.high, EEVEE_OFFSET | REG_EEVEE_TICKS_HIGH);  
  // Don't read any registers though, this is just the ack payload
  
  // Return success
  return 0;
}

//
// This function must be provided as an argument
// to all calls to stoneMalloc() and stoneFree()
// in order for garbage collection to work efficiently.
// This function pointer is used to identify the
// module to the garbage collection system.
//
int telemetryHook(struct eevee_payload *load, void **bp) {

  struct telemetry_stone *state;
  struct telemetry_header *telemetry_header;
  u32 now, delta;
  u8 N;
  u8 *packet;

  // If we've not bootstrapped yet, do so
  if((*bp) == NULL)
    telemetryInit(bp);

  // Convenience cast
  state = (struct telemetry_stone *)(*bp);

  // If we failed, get out of here.
  if(!state)
    return 1;

  // See if we are supposed to do anything?
  if(state->registers) {

    // The register list is non-null, so telemetry has been requested

    // See if we should send a packet
    NISHI_REG_READ(now, EEVEE_OFFSET | REG_EEVEE_CLOCK);

    if(now >= state->previousClock)
      delta = now - state->previousClock;
    else {

      // This can happen in two cases
      //   1) the clock has been reset
      //   2) the clock has rolled over
      //
      // Suppose previous clock was 0xffffffff
      // And now is 0x00000001
      // Then \Delta should be 2
      //
      // This takes the complement
      delta = ~(state->previousClock - now) + 1;
    }
    
    // Are we due (or past due) and have we not just recently fired?
    if(delta >= state->header.timestamp.words.low && !state->fired) {

      // Say that we've fired
      state->fired = 1;
      
      // Don't attempt to backdate...
      state->previousClock = now;
      
      // Read out the registers
      for(N = 0; N < state->Nreg; ++N)
	NISHI_REG_READ(state->registers[N].word, state->registers[N].addr);

      // Note that N = state->Nreg now.

      // Packets require annoying alignment issues
      // So there is a wrapper (that also lets us do dynamic or static packets)
      if(! (packet = mallocPacket(512)))
	return 1;
      
      // Populate the packet
      // DISPLACE is a macro that computes pointer offsets reliably.
      // (prevents easy errors in pointer arithmetic due to cast precedence)
      telemetry_header = (struct telemetry_header *) DISPLACE( DISPLACE( DISPLACE(packet, struct ether_header), struct ip), struct udphdr);
      
      // Set the mac address (inside our header, since it tracks the device ID)
      memcpy(telemetry_header->address.mac, NIFT_ipsystem.mac, ETH_ALEN);

      // Set the clock value
      NISHI_REG_READ(telemetry_header->timestamp.words.low,
		     EEVEE_OFFSET | REG_EEVEE_TICKS_LOW);
      NISHI_REG_READ(telemetry_header->timestamp.words.high,
		     EEVEE_OFFSET | REG_EEVEE_TICKS_HIGH);

      // Endian swap
      telemetry_header->timestamp.words.low = Xil_Htonl(telemetry_header->timestamp.words.low);
      telemetry_header->timestamp.words.high = Xil_Htonl(telemetry_header->timestamp.words.high);
      
      // Copy in the registers
      memcpy( DISPLACE(telemetry_header, struct telemetry_header),
	      state->registers,
	      N * sizeof(struct eevee_register));

      // Endian swap in outgoing
      for(N = 0; N < state->Nreg; ++N) {
	
	telemetry_header->registers[N].word = Xil_Htonl(telemetry_header->registers[N].word);
	telemetry_header->registers[N].addr = Xil_Htonl(telemetry_header->registers[N].addr);
      }
		  
      // Transmit the packet, with automatic arp resolution
      transmitPacket(packet,
		     EEVEE_SERVER_PORT,
		     state->header.address.dest.ip,
		     state->header.address.dest.port,
		     sizeof(struct telemetry_header) + N*sizeof(struct eevee_register));

      // Free the packet
      freePacket(packet);
    }
    else {

      // Reset the fired condition
      // (Didn't feel like wasting a look up and a conditional here).
      state->fired = 0;
    }
  }
  
  // Success
  return 0;
}

//////////// THE LINES BELOW CANNOT BE CHANGED ///////////////
#endif
#undef STONE
#endif
