/**
* @file CSysCall.cpp
* @author created by: Peter Hlavaty
*/

#include "StdAfx.h"

#include "CSysCall.h"
#include "../Common/IRQL.hpp"
#include "../Common/msr.h"

void* CSysCall::m_syscalls[MAX_PROCID] = { 0 };

EXTERN_C void sysenter();

CSysCall::CSysCall()
{
	RtlZeroMemory(m_syscalls, sizeof(m_syscalls));
}

CSysCall::~CSysCall()
{
	BYTE core_id = 0;
	CProcessorWalker cpu_w;
	while (cpu_w.NextCore(&core_id, core_id))
	{
		KeSetSystemAffinityThread(PROCID(core_id));

		HookSyscallMSR(m_syscalls[core_id]);

		DbgPrint("Unhooked. procid [%x] <=> syscall addr [%p]\n", core_id, m_syscalls[core_id]);

		core_id++;//follow with next core
	}
}

void CSysCall::Install()
{
	BYTE core_id = 0;
	CProcessorWalker cpu_w;
	while (cpu_w.NextCore(&core_id, core_id))
	{
		PerCoreAction(core_id);
		core_id++;//follow with next core
	}
}

void CSysCall::PerCoreAction( __in BYTE coreId )
{
	if (coreId < sizeof(m_syscalls))
	{
		KeSetSystemAffinityThread(PROCID(coreId));
		m_syscalls[coreId] = (void*)rdmsr(IA64_SYSENTER_EIP);
		HookSyscallMSR(sysenter);
		DbgPrint("Hooked. procid [%x] <=> syscall addr [%p]\n", coreId, m_syscalls[coreId]);
	}
}

//static 

void* CSysCall::GetSysCall( __in BYTE coreId )
{
	if (coreId > MAX_PROCID)
		return NULL;

	return CSysCall::m_syscalls[coreId];
}

void CSysCall::HookSyscallMSR(__in const void* hook)
{
	CDisableInterrupts idis;
	wrmsr(IA64_SYSENTER_EIP, (ULONG_PTR)hook);
}

//hook

LONG64 m_counter = 0;

EXTERN_C void* SysCallCallback( __inout ULONG_PTR* reg )
{
	InterlockedIncrement64(&m_counter);
	if (0 == (m_counter % (0x100000 / 4)))
		DbgPrint("syscalls are really painfull ... : %x\n", m_counter);

	ULONG core_id = KeGetCurrentProcessorNumber();
	if (core_id > MAX_PROCID)
		core_id = 0;//incorrect ... TODO ...

	return CSysCall::GetSysCall((BYTE)core_id);
}
