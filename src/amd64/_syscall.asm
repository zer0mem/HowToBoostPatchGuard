extrn SysCallCallback:proc

include common.inc

.code

sysenter proc
	swapgs	
	mov qword ptr gs:[Ring3RSP],rsp
	mov rsp,qword ptr gs:[Ring0RSP]
_hook:

	push rax
	pushfq
	pushaq

	mov rcx, rsp
	pushptr
	call SysCallCallback
	popptr

	add rax, _hook - sysenter
	xchg [rsp], rax
	popaq
	popfq

	xchg [rsp], rax
	ret
sysenter endp

end