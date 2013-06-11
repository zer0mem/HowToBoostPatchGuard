/**
 * @file Syseneter.h
 * @author created by: Peter Hlavaty
 */

#ifndef __SYSENETER_H__
#define __SYSENETER_H__

#include "../Common/Common.h"
#include "../Common/ProcessorWalker.hpp"

class CSysCall
{
public:
	CSysCall();
	~CSysCall();

	void Install();

	static void* GetSysCall(__in BYTE coreId);

protected:
	void PerCoreAction(__in BYTE coreId);
	void HookSyscallMSR(__in const void* hook);

private:
	static void* m_syscalls[MAX_PROCID];
};

#endif //__SYSENETER_H__
