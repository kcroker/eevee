#include "platform_definition.h"

#ifdef EEVEE_STONES

#include <malloc.h>
#include <string.h>
#include "xil_types.h"

#include "eevee_os.h"
#include "eevee_stones.h"

//
// USAGE
//
// Handlers should never send packets!  That's what the Hook is for.
//
// Any packets in process within a stone will be trampled by anything
// at lower level.  For instance, if an ARP query is required to fulfill
// a transmitPacket() request, the packet you were building is gone.
//
extern struct NIFT_eevee eevee;

int registerStone(char *name, stoneCallback_fp hook, stoneCallback_fp handler) {

  struct eevee_stone *stone;
  void *bp;

  // Try to allocate the eventual base pointer.
  // I do this first because I don't want to
  // unlink the stone from the list if I couldn't
  // get a base pointer.
  if( ! (bp = malloc(sizeof(void *))))
    return 2;

  // Try to make a new stone
  if( ! (stone = (struct eevee_stone *)malloc(sizeof(struct eevee_stone))))
    return 1;

  // Check for empty condition
  if(eevee.stones == NULL)
    stone->next = NULL;
  else
    stone->next = eevee.stones;

  // Always link at the head
  // XXX We need to add a search now to see if we've already added this module
  // We can't have multiple instances of a module now, as the garbage collection will
  // get confused!
  eevee.stones = stone;
    
  // Initialize it
  memcpy(stone->name, name, 8);
  stone->hook = hook;
  stone->handler = handler;
  stone->bp = (void **)bp;
  *(stone->bp) = NULL;
  stone->gchead = NULL;
  
  return 0;
}

int unregisterStone(u8 n) {

  // Unlinks the nth stone in the list
  // and tears it down.
  struct eevee_stone *stone, *prev;
  struct alloc_list *tmp;
  u16 retval = 0;
  
  prev = NULL;
  stone = eevee.stones;

  // Fail if we were empty, but tried to unregister
  if(!stone)
    return 1;

  // Traverse to the nth position
  for(; n > 0; --n) {

    // Fail if we can't go n deep
    if(!stone->next)
      return 1;

    // Otherwise advance
    prev = stone;
    stone = stone->next;
  }

  // We are now on the nth stone
  // Are we at the head of the list?
  if(!prev) {

    // If there is only one, then next will be NULL
    // So this is correct.
    eevee.stones = stone->next;
  }
  else {

    // Unlink this stone
    prev->next = stone->next;
  }

  // Teardown the stone with garbage collection
  // Free all others
  while(stone->gchead->older) {
    tmp = stone->gchead->older;
    retval += stone->gchead->size;
    free(stone->gchead);
    stone->gchead = tmp;
  }

  // Free the most recent one
  free(stone->gchead);

  // Null it
  stone->gchead = NULL;

  // That should have freed the stone's state
  // Now free the last 4 bytes used to abstract the bp
  free(stone->bp);

  // Now free the stone itself!
  free(stone);
  
  // Return the retval
  return retval;
}

//
// More useful deallocation function
// Complains differently if trying to free inappropriate things at inappropriate times
//
int stoneFree(void *mem, stoneCallback_fp who) {

  struct alloc_list *prev, *ptr;
  struct eevee_stone *stone;
    
  // Figure out who's garbage list we are using
  // (this can be optimized with a cache, so that only one lookup per module callback
  //  ever run)
  stone = eevee.stones;
  
  while(stone && (stone->hook != who))
    stone = stone->next;

  // We don't know who we are tracking...
  if(!stone)
    return 3;

  // If we've never called stoneMaloc, bail
  if(!stone->gchead)
    return 2;

  // Start with the SECOND most recent allocation
  ptr = stone->gchead;
  prev = NULL;
  
  // Note short-circuiting OR before null dereference!
  while(ptr && ptr->mem != mem) {

    prev = ptr;
    ptr = ptr->older; 
  }

  // Did we terminate because null?
  if(!ptr)
    return 1;

  // Okay, we terminated because we found a match
  // Did we match the head?
  if(prev == NULL) {

    // It is, so reassign the tail
    stone->gchead = ptr->older;
  }
  else {

    // It is not, so unlink as usual
    prev->older = ptr->older;
  }        
      
  // Free the allocation tracked by ptr
  free(ptr->mem);

  // And free the tracking of this allocation
  free(ptr);

  // Return success
  return 0;
}

//
// Presumably you want to keep a pointer to the tail of the list
// because you are usually deallocating memory you just allocated
//
void *stoneMalloc(u16 size, stoneCallback_fp who) {

  struct alloc_list *ptr;
  struct eevee_stone *stone;
  
  // Figure out who's garbage list we are using
  // (this can be optimized with a cache, so that only one lookup per module callback
  //  ever run)
  stone = eevee.stones;
  
  while(stone && (stone->hook != who))
    stone = stone->next;

  // We don't know who we are tracking...
  if(!stone)
    return NULL;
  
  // Is this the first malloc?
  if(!stone->gchead) {
    if(! (stone->gchead = (struct alloc_list *) malloc(sizeof(struct alloc_list))))
      return NULL;

    // The head of the list is always the most recent allocation
    stone->gchead->mem = stone->gchead;
    stone->gchead->size = sizeof(struct alloc_list);
    stone->gchead->older = NULL;
  }

  // Now lets allocate tracking for this specific request
  if(! (ptr = (struct alloc_list *) malloc(sizeof(struct alloc_list))))
    return NULL;

  // And try to allocate this specific request
  if(! (ptr->mem = malloc(size))) {

    // We failed, so teardown this storage we just did
    free(ptr);
    return NULL;
  }

  // We allocated it, so assign the size
  ptr->size = size;

  // Going in at the head, so its older becomes the previous gchead
  ptr->older = stone->gchead;

  // Assign it as the new head
  stone->gchead = ptr;
  
  // Return a pointer to the allocated block for use by the module
  return ptr->mem;
}
#endif
