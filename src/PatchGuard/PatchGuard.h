/**
 * @file PageGuard.h
 * @author created by: Peter Hlavaty
 */

#ifndef __PAGEGUARD_H__
#define __PAGEGUARD_H__

#include "../Common/Mdl.h"

#define PG_PROLOGUE 0x085131481131482e
#define PG_BASECODE 0xFFFF800000000000
#define PG_CRYPTED_CONTENT_OFF 0xC0
#define PG_SYSCALL_OFF 0x31500

#pragma pack(push, 1)

//like hammer to the eye ... probably just re-discovered -> too obvious ...
struct PAGEGUARD_KDPC : public _KDPC
{
	ULONG_PTR MagicXorAddr;
};

//PAGEGUARD_STRUCT have to be aligned to sizeof(ULONG_PTR) ... cause of above algorithms ...
struct PAGEGUARD_STRUCT
{
	ULONG_PTR Code[PG_CRYPTED_CONTENT_OFF / sizeof(ULONG_PTR)];
	ULONG Unknown1;
	ULONG SizeOfCodeInPtr;
	BYTE Unknown2[0x360 - 0xC0 - 8];
	ULONG_PTR CRC;
	BYTE Unknown3[0x38c - 0x360 - 8];
	ULONG SizeOfDataBlock;
	ULONG MainCodeRVA;
	BYTE Unknown4[0x3B4 - 0x38c - 8];
	ULONG RolByteInUlong;
	ULONG_PTR XorKey;
	BYTE Unknown5[0x3D0 - 0x3b4 - 4 - 8];
	ULONG SizeOfResources;
	ULONG Unknown6;
};

struct PAGEGUARD_PROLOGUE
{
	ULONG_PTR Code[3];
};

#pragma pack(pop)

#define PG_CRYPTED_STRUCT_SIZE (sizeof(PAGEGUARD_STRUCT) - offsetof(PAGEGUARD_STRUCT, Unknown1))

class CPageGuard
{
public:
	CPageGuard(__in const _KDPC* pgDPC);
	~CPageGuard();	
	
	static __checkReturn bool IsPatchGuardContext(__in const _KDPC* pgDPC);
	static void DecryptPageGuardStruct(__inout PAGEGUARD_STRUCT& pg);

	ULONG_PTR CalculateIntegrityHash();
	__checkReturn bool PatchData(__in ULONG offset, __in_bcount(size) void* mem, __in ULONG size);

	PAGEGUARD_STRUCT* GetStruct()
	{
		return &m_pgDecrypted;
	}


protected:
	__checkReturn bool ReXorData(__in ULONG offset, __in ULONG size);
	static ULONG_PTR RotateKey(__in ULONG_PTR key, __in ULONG pos, __in ULONG size);

protected:
	ULONG_PTR m_key;
	PAGEGUARD_STRUCT m_pgDecrypted;
	PAGEGUARD_STRUCT* m_pgPtr;
};

#endif //__PAGEGUARD_H__