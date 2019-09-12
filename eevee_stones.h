#include "platform_definition.h"

#ifdef EEVEE_STONES

#include "eevee_os.h"

// The stone system uses #pragma to fail out on accidental usage of malloc() and free()
#ifdef STONE
#pragma GCC poison malloc free realloc
#endif

// The rest of this stuff should only be defined once
#ifndef EEVEE_STONES_H
#define EEVEE_STONES_H

// Linked list for extensions (called stones ;) )
struct eevee_stone {

  // An identifying string for the stone
  char name[8];

  // Hook and handler
  int (*hook)(struct eevee_payload *, void **bp);
  int (*handler)(struct eevee_payload *, void **bp);

  // A pointer to 4 bytes of allocated memory.
  // This allocated memory (*bp) = NULL initially.
  // bp is passed to the stone, and it can store
  // its state there.  Note that the stone cannot
  // (easily) clobber the eevee_stone data
  // structure this way.
  void **bp;
    
  // Allocated memory and sizes, for reporting and garbage collection
  struct alloc_list *gchead;

  // The next stone
  struct eevee_stone *next;
};

// Backward linked list for garbage collection
// This is for efficiency, since we are usually freeing things we allocated recently
struct alloc_list {

  void *mem;
  u16 size;
  struct alloc_list *older;
};

// Convenience typedefs
typedef int (*stoneCallback_fp)(struct eevee_payload *, void **bp);

int registerStone(char *name, stoneCallback_fp hook, stoneCallback_fp handler);
int unregisterStone(u8 n);
void *stoneMalloc(u16 size, stoneCallback_fp who);
int stoneFree(void *mem, stoneCallback_fp who);

#endif
#endif
