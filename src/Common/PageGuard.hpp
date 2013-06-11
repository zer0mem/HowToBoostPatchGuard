/**
 * @file PageGuard.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PAGEGUARD_H__
#define __PAGEGUARD_H__

#include "HVCommon.h"
#include "Mdl.h"

#define PG_PROLOGUE 0x085131481131482e
#define PG_BASECODE 0xFFFF800000000000
#define PG_CRYPTED_CONTENT_OFF 0xC0
#define PG_SYSCALL_OFF 0x31500

#pragma pack(push, 1)

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
	CPageGuard(__in const _KDPC* pgDPC) : m_pgPtr(NULL)
	{
		if (!IsPatchGuardContext(pgDPC))
			return;

		m_pgPtr = (PAGEGUARD_STRUCT*)(PG_BASECODE | ((ULONG_PTR)(pgDPC->DeferredContext) ^ ((PAGEGUARD_KDPC*)pgDPC)->MagicXorAddr));
		m_pgDecrypted = *m_pgPtr;
		m_key = m_pgPtr->Code[0] ^ PG_PROLOGUE;

		DecryptPageGuardStruct(m_pgDecrypted);		
		
		DbgPrint("\nmagic page guard ctx %p\n", m_pgPtr);
	}

	~CPageGuard()
	{
		if (!m_pgPtr)
			return;

		m_pgDecrypted.CRC = CalculateIntegrityHash();
		
		*m_pgPtr = m_pgDecrypted;
		(void)ReXorData(offsetof(PAGEGUARD_STRUCT, Unknown2), PG_CRYPTED_STRUCT_SIZE - sizeof(ULONG_PTR));
		
		//xor also size + unkn ==> +1
		for (size_t i = 0; i < _countof(m_pgDecrypted.Code) + 1; i++)
			m_pgPtr->Code[i] ^= m_key;
	}
	

	static __checkReturn bool IsPatchGuardContext(__in const _KDPC* pgDPC)
	{
		const void* magic_addr = (void*)((ULONG_PTR)(pgDPC->DeferredContext) ^ ((PAGEGUARD_KDPC*)pgDPC)->MagicXorAddr);

		if (0xFFFFF00000000000 != ((ULONG_PTR)magic_addr & 0xFFFFF00000000000))
		{
			magic_addr = (const void*)((ULONG_PTR)magic_addr | PG_BASECODE);

			CMdl mdl(magic_addr, 3 * sizeof(ULONG_PTR));
			void* mem = mdl.Map();
			if (NULL != mem)
			{
				PAGEGUARD_PROLOGUE prologue;
				memcpy(&prologue, mem, sizeof(prologue));

				if (prologue.Code[1] && prologue.Code[2])
					return (0 == ((prologue.Code[1] ^ prologue.Code[2]) & 0x00FFFFFF00FFFFFF));
			}
		}

		return false;
	}

	ULONG_PTR CalculateIntegrityHash()
	{
		if (!m_pgPtr)
			return 0;

		ULONG_PTR crc = m_pgDecrypted.CRC;
		ULONG size_of_res = m_pgDecrypted.SizeOfResources;

		m_pgDecrypted.CRC = 0;
		m_pgDecrypted.SizeOfResources = 0;
		ULONG_PTR crc_key = m_pgDecrypted.XorKey;

		//crc on PAGEGUARD_STRUCT
		for (const ULONG_PTR* pg_data = (ULONG_PTR*)&m_pgDecrypted; 
			pg_data < (ULONG_PTR*)(&m_pgDecrypted + 1);
			pg_data++)
		{
			crc_key = ROL((crc_key ^ *pg_data), (BYTE)m_pgDecrypted.RolByteInUlong);
		}
		
		//crc on code
		for (ULONG i = PG_CRYPTED_STRUCT_SIZE / sizeof(ULONG_PTR); 
			i <= m_pgDecrypted.SizeOfCodeInPtr; 
			i++)
		{
			ULONG_PTR crc_val = ((ULONG_PTR*)m_pgPtr + _countof(m_pgPtr->Code))[i] ^ RotateKey(m_key, i, m_pgDecrypted.SizeOfCodeInPtr);
			
			crc_key = ROL((crc_key ^ crc_val), (BYTE)m_pgDecrypted.RolByteInUlong);
		}

		//crc on unencrypted data	
		for (ULONG i = m_pgDecrypted.SizeOfCodeInPtr + _countof(m_pgDecrypted.Code) + 1; 
			i < m_pgDecrypted.SizeOfDataBlock / sizeof(ULONG_PTR); 
			i++)
		{
			crc_key = ROL((crc_key ^ ((ULONG_PTR*)m_pgPtr)[i]), (BYTE)m_pgDecrypted.RolByteInUlong);
		}
		
		for (ULONG i = 0, bcount = m_pgDecrypted.SizeOfDataBlock % sizeof(ULONG_PTR);
			i < bcount; 
			i++)
		{
			crc_key= ROL((crc_key ^ ((BYTE*)m_pgPtr + m_pgDecrypted.SizeOfDataBlock - bcount)[i]), (BYTE)m_pgDecrypted.RolByteInUlong);			
		}

		m_pgDecrypted.CRC = crc;
		m_pgDecrypted.SizeOfResources = size_of_res;

		return crc_key;
	}

	__checkReturn bool PatchData(__in ULONG offset, __in_bcount(size) void* mem, __in ULONG size)
	{
		if (!m_pgPtr)
			return false;

		if (offset > m_pgDecrypted.SizeOfDataBlock || offset + size > m_pgDecrypted.SizeOfDataBlock)
			return false;
		
		//crypted ?
		if (offset < sizeof(m_pgDecrypted.Code) + m_pgDecrypted.SizeOfCodeInPtr * sizeof(ULONG_PTR))
		{
			//in struct ?
			if (offset < sizeof(m_pgDecrypted))
			{
				if (offset + size > sizeof(m_pgDecrypted))
					return false;

				memcpy((BYTE*)&m_pgDecrypted + offset, mem, size);
			}
			//just code
			else
			{
				if (!ReXorData(offset, size))
					return false;

				memcpy((BYTE*)m_pgPtr + offset, mem, size);				

				if (!ReXorData(offset, size))
					return false;
			}
		}
		else
		{
			memcpy((BYTE*)m_pgPtr + offset, mem, size);
		}

		m_pgDecrypted.CRC = CalculateIntegrityHash();
		return true;
	}

	const PAGEGUARD_STRUCT* GetStruct()
	{
		return &m_pgDecrypted;
	}

	static void DecryptPageGuardStruct(__inout PAGEGUARD_STRUCT& pg)
	{
		ULONG_PTR key = pg.Code[0] ^ PG_PROLOGUE;

		for (size_t i = 0; i < _countof(pg.Code); i++)
			pg.Code[i] ^= key;

		*(ULONG_PTR*)&pg.Unknown1 ^= key;

		//encode pg.<Unknown2, Unknown5>;
		for (ULONG i = pg.SizeOfCodeInPtr; i != 0; i--)
		{
			if (i * sizeof(ULONG_PTR) < sizeof(pg) - sizeof(pg.Code))
				((ULONG_PTR*)&pg + _countof(pg.Code))[i] ^= key;

			key = ROR(key, (BYTE)i);
		}

	}

protected:
	static ULONG_PTR RotateKey(__in ULONG_PTR key, __in ULONG pos, __in ULONG size)
	{
		for (; size != pos; size--)
			key = ROR(key, (BYTE)size);

		return key;
	}

	__checkReturn bool ReXorData(__in ULONG offset, __in ULONG size)
	{
		if (offset < sizeof(m_pgPtr->Code))
			return false;

		offset -= sizeof(m_pgPtr->Code);
		ULONG soff = offset / sizeof(ULONG_PTR);
		ULONG eoff = (offset + size + sizeof(ULONG_PTR) - 1) / sizeof(ULONG_PTR);

		if (soff > m_pgDecrypted.SizeOfCodeInPtr || 
			eoff > m_pgDecrypted.SizeOfCodeInPtr)
			return false;

		for (ULONG i = soff; i < eoff; i++)
			((ULONG_PTR*)m_pgPtr + _countof(m_pgPtr->Code))[i] ^= RotateKey(m_key, i, m_pgDecrypted.SizeOfCodeInPtr);

		return true;
	}

protected:
	ULONG_PTR m_key;
	PAGEGUARD_STRUCT m_pgDecrypted;
	PAGEGUARD_STRUCT* m_pgPtr;
};

#endif //__PAGEGUARD_H__