#include "StdAfx.h"

#include "src/Common/Common.h"
#include "src/Common/IRQL.hpp"
#include "./src/PatchGuardBoost/PatchGuardBoost.h"

CPatchGuardBoost* gPG = NULL;

void OnUnload(__in DRIVER_OBJECT* driverObject)
{
	if (gPG)
	{
		gPG->~CPatchGuardBoost();

		CDispatchLvl dispatch;
		free(gPG);
	}
}

NTSTATUS DriverEntry(__in DRIVER_OBJECT* driverObject, __in UNICODE_STRING* registryPath)
{
	driverObject->DriverUnload = OnUnload;

	{
		CDispatchLvl dispatch;
		gPG = (CPatchGuardBoost*)malloc(sizeof(*gPG));
	}

	if (gPG)
	{
		::new(gPG) CPatchGuardBoost();

		gPG->Boost();
	}

    return STATUS_SUCCESS;
} // end DriverEntry()
