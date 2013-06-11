/**
 * @file libc.cpp
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"
#include "Common.h"

#ifndef _LIBC_POOL_TAG
#define _LIBC_POOL_TAG	'llPm'
#endif

struct MEMPOOL
{
	size_t Size;	
	BYTE Data[];
};

EXTERN_C
__drv_when(return != NULL, __drv_allocatesMem(LIBPOOL))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* __cdecl malloc(__in size_t size)
{
	MEMPOOL* block = (MEMPOOL*)ExAllocatePoolWithTag(NonPagedPool, size + sizeof(MEMPOOL), _LIBC_POOL_TAG);
	if (block)
	{
		block->Size = size;
		return block->Data;
	}

	return NULL;
}

EXTERN_C
__drv_maxIRQL(DISPATCH_LEVEL)
void __cdecl free(__inout_opt __drv_freesMem(LIBPOOL) void *ptr)
{
	if (NULL != ptr)
		ExFreePoolWithTag(CONTAINING_RECORD(ptr, MEMPOOL, Data), _LIBC_POOL_TAG);
}

void __cdecl operator delete(void *ptr)
{
	//nop
}
