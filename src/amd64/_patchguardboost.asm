extrn DPCInvokerHook:proc
extrn ExAllocCheck:proc
extrn ExAllocFinal:proc

include common.inc

.code

dpcinvhook proc
	mov r9d, dword ptr [r12+0Ch]
	mov r8d, dword ptr [r12+8]
	mov rdx, qword ptr [rdi+20h]
	inc qword ptr [rsp]
	inc qword ptr [rsp]

	pushfq
	pushaq

	sub rsp, sizeof(qword) * 8
	call DPCInvokerHook
	add rsp, sizeof(qword) * 8

	popaq
	popfq
	ret
dpcinvhook endp

alloccheck proc
	pushfq
	pushaq

	sub rsp, sizeof(qword) * 8
	call ExAllocCheck
	add rsp, sizeof(qword) * 8

	popaq
	popfq

	inc qword ptr [rsp]
	inc qword ptr [rsp]
	inc qword ptr [rsp]
	pop rax
	
	sub rsp, sizeof(qword) * 8
	push rax	
	mov rax, offset allocfinal
	xchg rax, [rsp]

	push rbx
	push rsi
	push rdi
	push r12
	push r15
	sub rsp, 0A0h

	push rax
	ret
alloccheck endp

allocfinal proc
	add rsp, sizeof(qword) * 8
	pushfq
	pushaq

	mov rcx, rax
	sub rsp, sizeof(qword) * 8
	call ExAllocFinal
	add rsp, sizeof(qword) * 8

	popaq
	popfq
	ret
allocfinal endp

end