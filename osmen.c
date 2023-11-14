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

struct block_meta *first_sbrk, *last_sbrk;
struct block_meta *first_mmap, *last_mmap;

void split_block(struct block_meta *block, size_t size)
{
	// split the block in 2 parts(one allocated and one not allocated)
	struct block_meta *unused =
		(struct block_meta *)((char *)(block) + size + BLOCK_META_ALIGNEMENT);

	// set the fields and make the links between
	// the splitted blocks and "neighbour" blocks
	unused->status = STATUS_FREE;
	unused->prev = block;
	unused->next = block->next;
	unused->size = block->size - size - BLOCK_META_ALIGNEMENT;

	block->next = unused;
	block->size = size;

	// if the block was the last
	if (last_sbrk == block)
		last_sbrk = unused;
}

// allocating a block of memory based on the syscall used
// updating the coresponding lists

void *allocation(void *p, size_t size, size_t type, struct block_meta **first,
				 struct block_meta **last)
{
	// casting to block_meta type
	struct block_meta *data = p;

	// adding data to the allocated block
	data->size = size - BLOCK_META_ALIGNEMENT;
	data->next = NULL;
	data->status = type;

	// adding to list
	if (!(*first)) {
		// first allocation
		(*first) = data;
		(*first)->prev = NULL;
	} else {
		// making the linking between the allocated block
		// and the last one allocated with mmap
		(*last)->next = data;
		data->prev = (*last);
	}

	// now the last element of the mmap list is data
	(*last) = data;

	return (void *)((char *)p + BLOCK_META_ALIGNEMENT);
}

void *find_best(size_t size)
{
	struct block_meta *curr = first_sbrk;
	struct block_meta *block = NULL;
	size_t find_min = ULONG_MAX;

	// searching the best block from sbrk list
	while (curr) {
		// check if the block from sbrk list is free and it has a proper size
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
		if (block->size - size > BLOCK_META_ALIGNEMENT)
			split_block(block, size);

		block->status = STATUS_ALLOC;
		void *p = (void *)(block + 1);
		return p;
	}

	// if we could not find a block
	return NULL;
}

void *preallocation(void *p, size_t size)
{
	// casting to struct block_meta
	struct block_meta *data = (struct block_meta *)p;

	// set sbrk list
	first_sbrk = last_sbrk = data;

	// set header
	data->size = MMAP_THRESHOLD - BLOCK_META_ALIGNEMENT;
	data->status = STATUS_ALLOC;
	data->next = data->prev = NULL;

	// check if we do not use the entire preallocation space
	if (data->size - size > BLOCK_META_ALIGNEMENT)
		split_block(data, size);

	// the adress for the start of the payload
	return (void *)((char *)(data) + BLOCK_META_ALIGNEMENT);
}

void combine(struct block_meta *first, struct block_meta *second)
{
	// making the links
	first->next = second->next;
	first->size = first->size + second->size + BLOCK_META_ALIGNEMENT;

	// if second was the last block from the sbrk list
	if (second == last_sbrk)
		last_sbrk = first;
}

void *os_malloc(size_t size)
{
	// if the size is 0 we can't alloc memory
	if (size) {
		size_t block_size = ALIGN(size + BLOCK_META_ALIGNEMENT);
		size_t current_size = ALIGN(size);
		void *p = NULL;

		// preallocation
		if (!first_sbrk && block_size < MMAP_THRESHOLD) {
			// call sbrk for allocating
			p = sbrk(MMAP_THRESHOLD);

			// check the error code of the syscall
			DIE(p == ERROR, "sbrk failed");
			p = preallocation(p, current_size);
			return p;
		}

		// if the block is bigger than MMAP_THRESHOLD
		// we need to allocate memory with mmap
		if (block_size > MMAP_THRESHOLD) {
			p = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANON, -1, 0);

			// check if the syscall worked
			DIE(p == ERROR, "mmap failed");

			p = allocation(p, block_size, STATUS_MAPPED, &first_mmap,
						   &last_mmap);
			memset(p, 0, current_size);
			return p;
		}

		p = find_best(current_size);

		// we find a continuous memory zone
		if (p)
			return p;

		if (last_sbrk->status == STATUS_FREE) {
			// expending the last block
			size_t last = current_size - last_sbrk->size;

			p = sbrk(last);

			// check if the syscall worked
			DIE(p == ERROR, "sbrk");

			last_sbrk->size = current_size;
			last_sbrk->status = STATUS_ALLOC;

			// the address from the start of the payload
			return (void *)(last_sbrk + 1);
		}

		// allocate with sbrk
		p = sbrk(block_size);

		// check if the syscall worked
		DIE(p == ERROR, "sbrk failed");

		return allocation(p, block_size, STATUS_ALLOC, &first_sbrk, &last_sbrk);
	}
	return NULL;
}

void os_free(void *ptr)
{
	// checking if ptr is NULL
	if (ptr) {
		struct block_meta *data = (struct block_meta *)ptr - 1;
		struct block_meta *curr = NULL;
		struct block_meta *ant = NULL;

		// if the block was allocated with mmap
		if (data->status == STATUS_MAPPED) {
			curr = first_mmap;

			// searching into the mmap list for finding
			// the block behind the one that will be freed
			while (curr != data && curr) {
				ant = curr;
				curr = curr->next;
			}

			// removing the block from mmap list
			if (ant)
				ant->next = data->next;

			// update the first and the last block from mmap list
			// if it is necessary
			if (last_mmap == data)
				last_mmap = ant;
			if (first_mmap == data)
				first_mmap = first_mmap->next;

			munmap(data, data->size + BLOCK_META_ALIGNEMENT);
			return;
		}

		if (data->status == STATUS_ALLOC)
			data->status = STATUS_FREE;

		// linking with other blocks allocated with sbrk
		curr = first_sbrk;

		while (curr != data && curr) {
			ant = curr;
			curr = curr->next;
		}

		// checking if the anteriour block is freed
		if (ant && ant->status == STATUS_FREE) {
			// checking if the next is also freed
			if (data->next && data->next->status == STATUS_FREE) {
				// combine all three and reset the size of the block
				combine(ant, data->next);
				ant->size += BLOCK_META_ALIGNEMENT + data->size;
			} else {
				// combine anteriour and current
				combine(ant, data);
			}
		} else {
			if (data->next && data->next->status == STATUS_FREE)
				// combine current and the next one
				combine(data, data->next);
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	// total amount of memory to be allocated
	size_t total = nmemb * size;

	// overflow or parameter is zero
	if (total == 0 || total / nmemb != size || total / size != nmemb)
		return NULL;

	size_t block_size = ALIGN(total + BLOCK_META_ALIGNEMENT);
	size_t current_size = ALIGN(total);
	size_t page = getpagesize();
	void *p = NULL;

	if (!first_sbrk && block_size < page) {
		// call sbrk for allocating
		p = sbrk(MMAP_THRESHOLD);

		// check if the syscall worked
		DIE(p == ERROR, "sbrk failed");
		p = preallocation(p, current_size);
	} else {
		if (block_size > page) {
			p = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANON, -1, 0);

			// check if the syscall worked
			DIE(p == ERROR, "mmap failed");
			p = allocation(p, block_size, STATUS_MAPPED, &first_mmap,
						   &last_mmap);
		} else {
			p = find_best(current_size);
			if (!p) {
				if (last_sbrk->status == STATUS_FREE) {
					// expending the last block
					size_t last = current_size - last_sbrk->size;

					p = sbrk(last);

					// check if the syscall worked
					DIE(p == ERROR, "sbrk");

					// update the last block of sbrk list
					last_sbrk->size = current_size;
					last_sbrk->status = STATUS_ALLOC;

					// the address from the start of the payload
					p = last_sbrk + 1;
				} else {
					// allocate with sbrk
					p = sbrk(block_size);

					// check if the syscall worked
					DIE(p == ERROR, "sbrk failed");
					p = allocation(p, block_size, STATUS_ALLOC, &first_sbrk,
								   &last_sbrk);
				}
			}
		}
	}
	memset(p, 0, total);
	return p;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	size_t current_size = ALIGN(size);
	struct block_meta *data =
		(struct block_meta *)((char *)(ptr)-BLOCK_META_ALIGNEMENT);
	void *p = NULL;

	if (data->size == current_size)
		return ptr;

	if (data->status == STATUS_FREE)
		return NULL;

	if (current_size > data->size && data->status == STATUS_ALLOC) {
		if (data == last_sbrk) {
			// expending the last block
			size_t last = current_size - last_sbrk->size;

			p = sbrk(last);

			// check if the syscall worked
			DIE(p == ERROR, "sbrk");

			// update the last block of sbrk list
			last_sbrk->size = current_size;
			last_sbrk->status = STATUS_ALLOC;

			// the address from the start of the payload
			p = last_sbrk + 1;
			return p;
		}
	}

	p = os_malloc(size);
	if (size < data->size)
		memcpy(p, ptr, size);
	else
		memcpy(p, ptr, data->size);
	os_free(ptr);
	return p;
}
