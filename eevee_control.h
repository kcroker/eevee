#ifndef EEVEE_CONTROL_H
#define EEVEE_CONTROL_H

// *this* version of eeveeos protocol
#define EEVEE_VERSION_HARD 0xCafe

// Every time the protocol spec gets changed, the VERSION_SOFT gets incremented
#define EEVEE_VERSION_SOFT 0x0003
#define EEVEE_VERSION_MASK_SOFT 0x0000FFFF
#define EEVEE_VERSION_MASK_HARD 0xFFFF0000

// Register operation format:
//   Bits 0-1  (??, read, write, status: operator specifier)
//   Bit 2     (RESERVED)
//   Bit 3     Silent flag
//   Bit 4     Failure flag
//   Bit 5     No readback
// Flag bits for the register interface
#define EEVEE_OP_MASK_REG         0x0003 // 0-1 bits for the register operation
#define EEVEE_OP_MASK_SILENT      0x0004 // 2-nd bit position = 4
#define EEVEE_OP_MASK_FAILURE     0x0008 // 3-rd bit position = 8
#define EEVEE_OP_MASK_NOREADBACK  0x0010 // 4-th bit position = 16
#define EEVEE_OP_MASK_RESERVED    0x0020 // 5-th bit position = 32

// Masks for register/other operations
#define EEVEE_OP_REGISTER      0x003f  // bottom 6 bits (3 in flags, 3 in register op)
#define EEVEE_OP_OTHER         0xFFC0  // everything else
#define EEVEE_OP_SHIFT         6

// A null operation is reserved
#define EEVEE_READ 0x0001
#define EEVEE_WRITE 0x0002
#define EEVEE_STATUS 0x0003

// Things that we don't usually want to change
#define EEVEE_MAGIC_COOKIE 0x1337ca75
#define EEVEE_SERVER_PORT 1337
#define EEVEE_NBIC_PORT 1338

// Maximum length of IP header (incoming): 24 bytes
// Maximum length of UDP header (incoming): 8 bytes
#define EEVEE_MAX_PAYLOAD 1468  // 1500 - the above 

// Widths for register control protocol
#define EEVEE_WIDTH_REGISTER 4
#define EEVEE_WIDTH_OP 2
#define EEVEE_WIDTH_WIDTH 2
#define EEVEE_WIDTH_DATALEN 2
#define EEVEE_WIDTH_SEQNUM 4

#endif
