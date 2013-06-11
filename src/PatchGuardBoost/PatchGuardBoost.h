/**
 * @file PatchGuardBoost.h
 * @author created by: Peter Hlavaty
 */

#ifndef __PATCHGUARDBOOST_H__
#define __PATCHGUARDBOOST_H__

#include "../Common/Common.h"
#include "../Common/DPC.hpp"
#include "../SYSCALL/CSysCall.h"
#include "../Common/ColdPatcher.hpp"

class CPatchGuardBoost : protected COneLoopDPC
{
public:
	CPatchGuardBoost();
	~CPatchGuardBoost();

	void Boost();

	static CColdPatcher* DpcHook()
	{
		return (CColdPatcher*)m_dpcHookMem;
	}

protected:
	virtual void CustomDPC(
		__in struct _KDPC* Dpc, 
		__in void* DeferredContext, 
		__in_opt void* SystemArgument1, 
		__in_opt void* SystemArgument2);

private:
	static BYTE m_dpcHookMem[sizeof(CColdPatcher)];
	CSysCall m_syscall;
};

#endif //__PATCHGUARDBOOST_H__