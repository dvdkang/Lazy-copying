#include "lazycopy.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define NUM_TESTS 2000
#define NUM_WRITES 100

size_t time_us();

void run_tests(int** originals, int** copies, bool eager);

int main() {
  // Initialize the lazy copying chunk code
  chunk_startup();

  // Set up for tests of both eager and lazy copying
  int* eager_originals[NUM_TESTS];
  int* eager_copies[NUM_TESTS];
  int* lazy_originals[NUM_TESTS];
  int* lazy_copies[NUM_TESTS];

  // Run the tests with eager copying
  run_tests(eager_originals, eager_copies, true);

  // Run the tests with lazy copying
  run_tests(lazy_originals, lazy_copies, false);

  // Compare values in the two sets of originals and copies to check for differences
  for (size_t i = 0; i < NUM_TESTS; i++) {
    for (size_t j = 0; j < CHUNKSIZE / sizeof(int); j++) {
      if (eager_originals[i][j] != lazy_originals[i][j] ||
          eager_copies[i][j] != lazy_copies[i][j]) {
        printf("Error! Lazy copying appears to be broken.\n");
        return 1;
      }
    }
  }

  return 0;
}

void run_tests(int** originals, int** copies, bool eager) {
  // Seed the random number generator with a known starting point
  srand(42);

  // Allocate original chunks and fill each with random values
  for (size_t i = 0; i < NUM_TESTS; i++) {
    originals[i] = chunk_alloc();
    for (size_t j = 0; j < NUM_TESTS / sizeof(int); j++) {
      originals[i][j] = rand();
    }
  }

  // Get the start time for copying
  size_t copy_start_time = time_us();

  // Copy each chunk eagerly
  for (size_t i = 0; i < NUM_TESTS; i++) {
    if (eager) {
      copies[i] = chunk_copy_eager(originals[i]);
    } else {
      copies[i] = chunk_copy_lazy(originals[i]);
    }
  }

  // Get the end time for eager copying
  size_t copy_end_time = time_us();

  // Make some random writes to the eagerly-copied chunks
  for (size_t i = 0; i < NUM_WRITES; i++) {
    // Write to either the original or the copy, chosen at random
    bool write_original = rand() % 2 == 0;

    // Pick a random chunk to write to
    size_t chunk_index = rand() % NUM_TESTS;

    // Pick a random offset into the chunk to write
    size_t chunk_offset = rand() % (CHUNKSIZE / sizeof(int));

    // Choose a random value to write
    int value = rand();

    // Do the write
    if (write_original) {
      originals[chunk_index][chunk_offset] = value;
    } else {
      copies[chunk_index][chunk_offset] = value;
    }
  }

  // Get the end time for writing
  size_t write_end_time = time_us();

  // Print timing information
  printf("%s Copying: %luus\n", eager ? "Eager" : "Lazy", copy_end_time - copy_start_time);
  printf("%s Writing: %luus\n", eager ? "Eager" : "Lazy", write_end_time - copy_end_time);
}

// Get the time in microseconds
size_t time_us() {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) == -1) {
    perror("gettimeofday");
    exit(2);
  }

  // Convert timeval values to microseconds
  return tv.tv_sec * 1000000 + tv.tv_usec;
}
