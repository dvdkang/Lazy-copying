#define _GNU_SOURCE
#include "lazycopy.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// global variable to hold addresses
typedef struct linked_list {
  struct node* head;
} linked_list_t;

typedef struct node {
  struct node* next;
  void* org_pointer;
  void* copy_pointer;
  intptr_t org_addr;
  intptr_t copy_addr;
} node_t;

linked_list_t* addrsholder;

void seg_handler(int signal, siginfo_t* info, void* ctx);
/**
 * This function will be called at startup so you can set up a signal handler.
 */
void chunk_startup() {
  // malloc for our linked list
  addrsholder = (linked_list_t*)malloc(sizeof(linked_list_t*));
  struct sigaction sa;
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_sigaction = seg_handler;
  sa.sa_flags = SA_SIGINFO;

  if (sigaction(SIGSEGV, &sa, NULL) != 0) {
    perror("Sigaction failed");
    exit(2);
  }
}

void seg_handler(int signal, siginfo_t* info, void* ctx) {
  // malloc space for new node to traverse through while loop
  node_t* traverse = (node_t*)malloc(sizeof(node_t*));
  traverse = addrsholder->head;
  // address of where seg fault occurs
  intptr_t seg_pntr = (intptr_t)(info->si_addr);
  // traverse through linked list until address is found
  while (traverse != NULL) {
    // condition to compare the address of the seg fault and the original address
    if (seg_pntr >= traverse->org_addr && seg_pntr <= traverse->org_addr + (CHUNKSIZE)) {
      // malloc space for new address
      intptr_t* tempaddr = malloc(CHUNKSIZE);
      // copies contents of pointer into new tempaddr
      memcpy(tempaddr, traverse->org_pointer, CHUNKSIZE);
      // replace mapping of pointer into new memory space and changed to read/write.
      void* newcpy = mmap(traverse->org_pointer, CHUNKSIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0);

      // checks if mmap worked correctly
      if (newcpy == MAP_FAILED) {
        perror("mmap() failed");
        exit(2);
      }
      // copies contents of tempaddr to pointer
      memcpy(traverse->org_pointer, tempaddr, CHUNKSIZE);
      // changes other pointer to read/write as well
      mprotect(traverse->copy_pointer, CHUNKSIZE, PROT_READ | PROT_WRITE);

      break;
    }
    // condition to compare the address of the seg fault and the copy address
    if (seg_pntr >= traverse->copy_addr && seg_pntr <= traverse->copy_addr + (CHUNKSIZE)) {
      // malloc space for new address
      intptr_t* tempaddr = malloc(CHUNKSIZE);
      // copies contents of pointer into new tempaddr
      memcpy(tempaddr, traverse->copy_pointer, CHUNKSIZE);
      // replace mapping of pointer into new memory space and changed to read/write.
      void* newcpy = mmap(traverse->copy_pointer, CHUNKSIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0);

      // checks if mmap worked correctly
      if (newcpy == MAP_FAILED) {
        perror("mmap() failed");
        exit(2);
      }
      // copies contents of tempaddr to pointer
      memcpy(traverse->copy_pointer, tempaddr, CHUNKSIZE);
      // changes other pointer to read/write as well
      mprotect(traverse->org_pointer, CHUNKSIZE, PROT_READ | PROT_WRITE);

      break;
    }
    // moves to next node of linked list
    traverse = traverse->next;
  }
}

/**
 * This function should return a new chunk of memory for use.
 *
 * \returns a pointer to the beginning of a 64KB chunk of memory that can be read, written, and
 * copied
 */
void* chunk_alloc() {
  // Call mmap to request a new chunk of memory. See comments below for description of arguments.
  void* result = mmap(NULL, CHUNKSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  // Arguments:
  //   NULL: this is the address we'd like to map at. By passing null, we're asking the OS to
  //   decide. CHUNKSIZE: This is the size of the new mapping in bytes. PROT_READ | PROT_WRITE: This
  //   makes the new reading readable and writable MAP_ANONYMOUS | MAP_SHARED: This maps a new
  //   mapping to cleared memory instead of a file,
  //                               which is another use for mmap. MAP_SHARED makes it possible for
  //                               us to create shared mapstruct sigactionpass -1 here.
  //   0: This doesn't matter. It would be the offset into a file, but we aren't using one.

  // Check for an error
  if (result == MAP_FAILED) {
    perror("mmap failed in chunk_alloc");
    exit(2);
  }

  // Everything is okay. Return the pointer.
  return result;
}

/**
 * Create a copy of a chunk by copying values eagerly.
 *
 * \param chunk This parameter points to the beginning of a chunk returned from chunk_alloc()
 * \returns a pointer to the beginning of a new chunk that holds a copy of the values from
 *   the original chunk.
 */
void* chunk_copy_eager(void* chunk) {
  // First, we'll allocate a new chunk to copy to
  void* new_chunk = chunk_alloc();

  // Now copy the data
  memcpy(new_chunk, chunk, CHUNKSIZE);

  // Return the new chunk
  return new_chunk;
}

/**struct sigaction
 * Create a copy of a chunk by copying values lazily.
 *
 * \param chunk This parameter points to the beginning of a chunk returned from chunk_alloc()
 * \returns a pointer to the beginning of a new chunk that holds a copy of the values from
 *   the original chunk.
 */
void* chunk_copy_lazy(void* chunk) {
  // Just to make sure your code works, this implementation currently calls the eager copy version
  // return chunk_copy_eager(chunk);
  // creates a duplicate mapping of the chunk passed in
  void* newadd = mremap(chunk, 0, CHUNKSIZE, MREMAP_MAYMOVE, 0);
  // verifies that mremap worked correctly
  if (newadd == MAP_FAILED) {
    perror("mremap() failed");
    exit(2);
  }

  // makes both mappings as read-only
  mprotect(chunk, CHUNKSIZE, PROT_READ);
  mprotect(newadd, CHUNKSIZE, PROT_READ);

  // mallocs space for new node that we will be using for our universal linked list
  node_t* new = (node_t*)malloc(sizeof(node_t));

  // assign addresses of original and copy mappings into the node we just malloced
  new->copy_addr = (intptr_t)newadd;
  new->copy_pointer = newadd;
  new->org_addr = (intptr_t)chunk;
  new->org_pointer = chunk;

  // assign node into linked list
  new->next = addrsholder->head;
  addrsholder->head = new;

  // Your implementation should do the following:
  // 1. Use mremap to create a duplicate mapping of the chunk passed in
  // 2. Mark both mappings as read-only
  // 3. Keep some record of both lazy copies so you can make them writable later.
  //    At a minimum, you'll need to know where the chunk begins and ends.
  // TODO: Global variable to keep record of address

  // Later, if either copy is written to you will need to:
  // 1. Save the contents of the chunk elsewhere (a local array works well)
  // 2. Use mmap to make a writable mapping at the location of the chunk that was written
  // 3. Restore the contents of the chunk to the new writable mapping
  return newadd;
}
// Keep some record of both lazy copies so you can make them w