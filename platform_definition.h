// Target architecture
//
// Uncomment the one you want.
#define SERIES7
// #define SPARTAN6

// Eevee works well with these stack and heap sizes
// Notice that these will override the specifications given in
// the generated lscript.ld
//#define _STACK_SIZE = 0x1400
//#define _HEAP_SIZE = 0x1400
  
// Use a static outgoing packet buffer?
// This guarantees that outgoing packets will always be sent
// since nothing is allocated off of the heap.
#define STATIC_PACKET_BUFFER

// It also needs to be less than the FIFO's for inbound and outbound data
// in the uBlaze design.
// This NEEDS to be divisible by 4, or else you will choke and die
// Must also be large enough to hold an etherframe. So 1518 + 2 -> 1520
#define ETH_MTU 1520

// This is the above number divided by 4
#define ETH_MTU_D4 380

// Disable the module system
#undef EEVEE_STONES

// List of modules you want compiled in and run at startup
// (can later, in principle, be unhooked but the data segment will still have
//  their code present)
#ifdef EEVEE_STONES

#define TELEMETRY_STONE

#endif
