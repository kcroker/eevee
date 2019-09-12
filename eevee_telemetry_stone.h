#include "platform_definition.h"

#ifdef EEVEE_STONES
#ifdef TELEMETRY_STONE

#ifndef EEVEE_TELEMETRY_STONE_H
#define EEVEE_TELEMETRY_STONE_H

// This is just the top bit
#define TELEMETRY_OFFSET 0x0001

//
// For simplicity, this is also the structure of the
// telemetry packet itself!
//
struct telemetry_header {

  // Telemetry Request: Destination to send telemetry
  // Telemetry Packet: Source board mac address (unique ID)
  union {

    struct {
      ip4_t ip;
      u16 port;
    } dest;

    u8 mac[6];

    // uBlaze architecture (32 bits) pads out to 4 bytes
    // We have to pad inside the structure since it is an aggregate type.
    // Since this is a union, this should be 8
    u8 padding[8];
    
  } address;

  // Telemetry Request: Scaled clock interval to send packets
  // Telemetry Packet: Ticks (64-bit, uptime) value when telemetry was taken
  union {

    struct {
      u32 high;
      u32 low;
    } words;

    u8 bytes[8];
    
  } timestamp;
 
  // Telemetry Request / Packet: Registers to report
  struct eevee_register registers[0];
};

struct telemetry_stone {

  u32 previousClock;
  u8 Nreg;
  u8 fired;
  
  struct telemetry_header header;
  struct eevee_register *registers;
};

// These cannot be static because they need to be called outside of this context
int telemetryHook(struct eevee_payload *payload, void **);
int telemetryHandler(struct eevee_payload *payload, void **);

#endif
#endif
#endif
