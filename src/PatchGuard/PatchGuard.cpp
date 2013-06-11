/**
* @file PageGuard.cpp
* @author created by: Peter Hlavaty
*/

#include "StdAfx.h"
#include "PatchGuard.h"
#include "../Common/instrinsics.h"

CPageGuard::CPageGuard(__in const _KDPC* pgDPC) : m_pgPtr(NULL)
{
	if (!IsPatchGuardContext(pgDPC))
		return;

	//... not bad ...
	m_pgPtr = (PAGEGUARD_STRUCT*)(PG_BASECODE | ((ULONG_PTR)(pgDPC->DeferredContext) ^ ((PAGEGUARD_KDPC*)pgDPC)->MagicXorAddr));
	DbgPrint("\nmagic page guard ctx %p\n", m_pgPtr);

	m_pgDecrypted = *m_pgPtr;
	m_key = m_pgPtr->Code[0] ^ PG_PROLOGUE;

	DecryptPageGuardStruct(m_pgDecrypted);
}

CPageGuard::~CPageGuard()
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

//simple heur
__checkReturn bool CPageGuard::IsPatchGuardContext(__in const _KDPC* pgDPC)
{
	ULONG_PTR magic_delta = (ULONG_PTR)(pgDPC->DeferredContext) ^ ((PAGEGUARD_KDPC*)pgDPC)->MagicXorAddr;

	if (0xFFFFF00000000000 != (magic_delta & 0xFFFFF00000000000))
	{
		const void* pg_context = (const void*)((ULONG_PTR)magic_delta | PG_BASECODE);

		CMdl mdl(pg_context, 3 * sizeof(ULONG_PTR));
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

void CPageGuard::DecryptPageGuardStruct(__inout PAGEGUARD_STRUCT& pg)
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

ULONG_PTR CPageGuard::CalculateIntegrityHash()
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

__checkReturn bool CPageGuard::PatchData(__in ULONG offset, __in_bcount(size) void* mem, __in ULONG size)
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

__checkReturn bool CPageGuard::ReXorData(__in ULONG offset, __in ULONG size)
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

ULONG_PTR CPageGuard::RotateKey(__in ULONG_PTR key, __in ULONG pos, __in ULONG size)
{
	//i guess smth clever than for cycle can be invented, but for this purpose good enough :P
	for (; size != pos; size--)
		key = ROR(key, (BYTE)size);

	return key;
}
