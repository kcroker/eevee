// Target architecture
//
// Uncomment the one you want.
#define SERIES7
// #define SPARTAN6

// Eevee works well with these stack and heap sizes
// Notice that these will override the specifications given in
// the generated lscript.ld
#define _STACK_SIZE = 0x1000
#define _HEAP_SIZE = 0x1000
  
// Use a static outgoing packet buffer?
// This guarantees that outgoing packets will always be sent
// since nothing is allocated off of the heap.
#define STATIC_PACKET_BUFFER

// It also needs to be less than the FIFO's for inbound and outbound data
// in the uBlaze design.
// This NEEDS to be divisible by 4, or else you will choke and die
// #define MAX_PACKET_SIZE 512
#define MAX_PACKET_SIZE 1518

// Enable the module system
#define EEVEE_STONES

// List of modules you want compiled in and run at startup
// (can later, in principle, be unhooked but the data segment will still have
//  their code present)
#define TELEMETRY_STONE
