// SPDX-License-Identifier: BSD-3-Clause
#include "osmem.h"
#define ALIGNMENT 8
#include <block_meta.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define BLOCK_META_SIZE (sizeof(struct block_meta))
#define BLOCK_META_ALIGNEMENT ALIGN(BLOCK_META_SIZE)
#define ERROR ((void *)-1)

struct block_meta *first_heap, *last_heap;
struct block_meta *first_mmap, *last_mmap;

/* Allocates memory using mmap() and inserts it into mmap list. */
void *mmap_allocation(size_t size) {
    // allocate with mmap
    void *p =
        mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    // check if the syscall worked
    DIE(p == ERROR, "mmap failed");

    // casting to block_meta type
    struct block_meta *data = p;

    // adding data to the allocated block
    data->size = size - BLOCK_META_ALIGNEMENT;
    data->next = NULL;
    data->status = STATUS_MAPPED;

    // adding to list
    if (!first_mmap) {
        // first allocation
        first_mmap = data;
    } else {
        /* making the linking between the allocated block and the last
        one allocated with mmap */
        last_mmap->next = data;
        // data->prev = last_mmap;
    }

    // now the last element of the mmap list is data
    last_mmap = data;

    return (void *)((char *)p + BLOCK_META_ALIGNEMENT);
}

void *heap_allocation(size_t size) {
    // allocate with mmap
    void *p = sbrk(size);

    // check if the syscall worked
    DIE(p == ERROR, "sbrk failed");

    // casting to block_meta type
    struct block_meta *data = p;

    // adding data to the allocated block
    data->size = size - BLOCK_META_ALIGNEMENT;
    data->next = NULL;
    data->status = STATUS_ALLOC;

    // adding to list
    if (!first_heap) {
        // first allocation
        first_heap = data;
    } else {
        /* making the linking between the allocated block and the last one
        allocated with mmap */
        last_heap->next = data;
        data->prev = last_heap;
    }

    // now the last element of the mmap list is data
    last_heap = data;

    return (void *)((char *)p + BLOCK_META_ALIGNEMENT);
}

void *find_best(size_t size) {
    struct block_meta *curr = first_heap;
    struct block_meta *block = NULL;
    size_t find_min = ULONG_MAX;

    // searching the best block from heap list
    while (curr) {
        // check if the block from heap list is free and it has a proper size
        // and it has a smaller size than the previous proper one
        if (curr->status == STATUS_FREE && curr->size >= size &&
            curr->size - size <= find_min) {
            block = curr;
            find_min = curr->size - size;
        }
        curr = curr->next;
    }

    // splitting the block if it is too big
    if (block) {
        if (block->size - size > BLOCK_META_ALIGNEMENT) {
            split_block(block, size);
        }

        block->status = STATUS_ALLOC;
        void *p = (void *)(block + 1);
        return p;
    }

    // if we could not find a block
    return NULL;
}

void split_block(struct block_meta *block, size_t size) {
    // split the block in 2 parts(one allocated and one not allocated)
    struct block_meta *unused =
        (struct block_meta *)((char *)(block) + size + BLOCK_META_ALIGNEMENT);

    /*set the fields and make the links between
        the splitted blocks and "neighbour" blocks*/
    unused->status = STATUS_FREE;
    unused->prev = block;
    unused->next = block->next;
    unused->size = block->size - size - BLOCK_META_ALIGNEMENT;

    block->next = unused;
    block->size = size;

    // if the block was the last
    if (last_heap == block) {
        last_heap = unused;
    }
}

void *preallocation(size_t size) {
    // call sbrk for allocating
    void *p = sbrk(MMAP_THRESHOLD);

    // check the error code of the syscall
    DIE(p == ERROR, "sbrk failed");

    // casting to struct block_meta
    struct block_meta *data = (struct block_meta *)p;

    // set heap list
    first_heap = last_heap = data;

    // set header
    data->size = MMAP_THRESHOLD - BLOCK_META_ALIGNEMENT;
    data->status = STATUS_ALLOC;
    data->next = NULL;
    data->prev = NULL;

    /* check if we do not use the entire preallocation space */
    if (data->size - size > BLOCK_META_ALIGNEMENT) {
        split_block(data, size);
    }

    // the adress for the start of the payload
    return (void *)((char *)(data) + BLOCK_META_ALIGNEMENT);
}

void *last_block_allocation(size_t size) {
    size_t remaining = size - last_heap->size;
    void *ret = sbrk(remaining);

    DIE(ret == ERROR, "sbrk");

    last_heap->size = size;
    last_heap->status = STATUS_ALLOC;

    // Return a pointer to the start of the payload
    return (void *)(last_heap + 1);
}

void heap_coalesce(struct block_meta *first, struct block_meta *second) {
    // making the links
    first->next = second->next;
    first->size = first->size + second->size + BLOCK_META_ALIGNEMENT;

    // if second was the last block from the heap list
    if (second == last_heap) {
        last_heap = second;
    }
}

/* Allocates size bytes of memory */
void *os_malloc(size_t size) {
    // if the size is <= 0 we can't alloc memory
    if (size <= 0) {
        return NULL;
    }

    size_t block_size = ALIGN(size + BLOCK_META_ALIGNEMENT);
    size_t current_size = ALIGN(size);

    // preallocation
    if (!first_heap && block_size < MMAP_THRESHOLD)
        return preallocation(current_size);

    void *p = NULL;

    /* if the block is bigger than MMAP_THRESHOLD
        we need to allocate memory with mmap */
    if (block_size > MMAP_THRESHOLD) {
        p = mmap_allocation(block_size);
        memset(p, 0, current_size);
        return p;
    }

    p = find_best(current_size);
    if (p) {
        // we find a continuous memory zone
        return p;
    }

    if (last_heap->status == STATUS_FREE) {
        // expending the last block
        return last_block_allocation(current_size);
    }

    return heap_allocation(block_size);
}

/* Frees memory of ptr */
void os_free(void *ptr) {
    // Check if ptr is NULL
    if (ptr) {
        struct block_meta *curr, *ant = NULL;
        struct block_meta *data = (struct block_meta *)ptr - 1;

        // if the block was allocated with mmap
        if (data->status == STATUS_MAPPED) {
            curr = first_mmap;

            /* searching into the mmap list for finding
            the block behind the one that will be freed */
            while (curr != data && curr) {
                ant = curr;
                curr = curr->next;
            }

            // removing the block from mmap list
            if (ant) {
                ant->next = data->next;
            }

            // update the first and the last block from mmap list
            // if it is necessary
            if (first_mmap == data) {
                first_mmap = first_mmap->next;
            }

            if (last_mmap == data) {
                last_mmap = ant;
            }

            munmap(data, data->size + BLOCK_META_ALIGNEMENT);
            return;
        }

        if (data->status == STATUS_ALLOC) {
            data->status = STATUS_FREE;
        }
        // linking with other blocks allocated with sbrk
        curr = first_heap;

        while (curr != data && curr) {
            ant = curr;
            curr = curr->next;
        }

        // Coalesce free blocks together
        if (data->next != NULL && ant != NULL &&
            data->next->status == STATUS_FREE && ant->status == STATUS_FREE) {
            // Coalesce all three blocks (prev, current, next) free blocks
            heap_coalesce(ant, data->next);
            ant->size += BLOCK_META_ALIGNEMENT + data->size;
        } else if (curr != NULL && ant != NULL && ant->status == STATUS_FREE) {
            // Coalesce previous and current
            heap_coalesce(ant, data);
        } else if (data->next != NULL && data->next->status == STATUS_FREE) {
            // Coalesce current and next
            heap_coalesce(data, data->next);
        }
    }
}

/* Allocates size bytes of memory and initializes the memory to ZERO */
void *os_calloc(size_t nmemb, size_t size) { return NULL; }

/* Reallocates pointer ptr to exactly size bytes of memory */
void *os_realloc(void *ptr, size_t size) { return NULL; }
