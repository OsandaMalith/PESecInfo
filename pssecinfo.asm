.386
.model flat,stdcall
option casemap:none
include windows.inc
include kernel32.inc
include user32.inc
include imagehlp.inc
include msvcrt.inc
include macros.asm
include shell32.inc

includelib user32.lib
includelib kernel32.lib
includelib imagehlp.lib
includelib msvcrt.lib
includelib shell32.lib

isDEP proto PE:LOADED_IMAGE
isCFG proto PE:LOADED_IMAGE
isDotNet proto PE:LOADED_IMAGE
isIsolation proto PE:LOADED_IMAGE
checkPE proto PE:LOADED_IMAGE
checkArch proto PE:LOADED_IMAGE
isDynamicBase2 proto PE:LOADED_IMAGE
isAuth proto PE:LOADED_IMAGE
disableAslr proto PE:LOADED_IMAGE
disableDep proto PE:LOADED_IMAGE
enableAslr proto PE:LOADED_IMAGE
enableDep proto PE:LOADED_IMAGE

system PROTO C, :PTR BYTE

.data
command BYTE "color 17",0
bin db "cfg.exe",0
crlf db 13, 10, 0 
banner \
db  13, 10
db  "           \\\     PE Sec Info		        ", 13, 10
db  "    .---.  ///     Coded by @OsandaMalith  ", 13, 10
db  "   (:::::)(_)():   https://osandamalith.com", 13, 10
db  "    `---'  \\\   ", 13, 10
db  "           ///   ", 13, 10, 0

.data?
szArglist dd ?
buf db 1024 DUP (?)
fname db 20 dup(?) 

.code
start proc 
	LOCAL PE:LOADED_IMAGE	
	SetConsoleCaption chr$("PE Sec Info")
	invoke system, addr command
	invoke crt_printf, addr banner
	
	call GetCommandLineW        ; EAX = pointer to the command line

    lea ecx, dword ptr[ebp - 4] ; Get the current address of [ebp-4]
    push ecx                    ; int *pNumArgs (Pointer to a SDWORD, here at ebp-4)
    push eax                    ; LPCWSTR lpCmdLine (from GetCommandLineW)
    call CommandLineToArgvW

    mov [szArglist], eax        ; Store the result of CommandLineToArgvW (at least for LocalFree)

    mov esi, eax                ; ESI = address of a pointer (the first element in szArglist)
    mov ebx, [ebp-4]            ; Countdown the number of arguments
	.if ebx < 2h
   		invoke crt_printf,chr$("[!] Enter a valid PE File")
   		jmp Help
   	.elseif ebx == 2h
   		invoke WideCharToMultiByte, 0, 0, [esi] + 4, -1, offset buf, sizeof buf, NULL, NULL
   	   	.if !cmpi$("-h", addr buf)
			jmp Help
		.else	
   		jmp Begin
   		.endif
   	.elseif ebx == 4h
   		invoke WideCharToMultiByte, 0, 0, [esi] + 8, -1, offset buf, sizeof buf, NULL, NULL
   		.if !cmpi$("-d", addr buf)
   			invoke WideCharToMultiByte, 0, 0, [esi] + 0ch, -1, offset buf, sizeof buf, NULL, NULL
			.if !cmpi$("aslr", addr buf)
				invoke WideCharToMultiByte, 0, 0, [esi] + 4, -1, offset buf, sizeof buf, NULL, NULL
				invoke MapAndLoad, addr buf, NULL, addr PE, NULL, NULL
				invoke disableAslr,PE
				jmp Exit
			.endif
			.if !cmpi$("dep", addr buf)
				invoke WideCharToMultiByte, 0, 0, [esi] + 4, -1, offset buf, sizeof buf, NULL, NULL
				invoke MapAndLoad, addr buf, NULL, addr PE, NULL, NULL
				invoke disableDep,PE
				jmp Exit
			.endif	
		.endif	
   		.if cmpi$("-e", addr buf) == NULL
   			invoke WideCharToMultiByte, 0, 0, [esi] + 0ch, -1, offset buf, sizeof buf, NULL, NULL
			.if !cmpi$("aslr", addr buf)
				invoke WideCharToMultiByte, 0, 0, [esi] + 4, -1, offset buf, sizeof buf, NULL, NULL
				invoke MapAndLoad, addr buf, NULL, addr PE, NULL, NULL
				invoke enableAslr,PE
				jmp Exit
			.endif
			.if !cmpi$("dep", addr buf)
				invoke WideCharToMultiByte, 0, 0, [esi] + 4, -1, offset buf, sizeof buf, NULL, NULL
				invoke MapAndLoad, addr buf, NULL, addr PE, NULL, NULL
				invoke enableDep,PE
				jmp Exit
			.endif
		.endif
   	.else
   		jmp Help
   	.endif
Help:
	printf("\n[?] Usage: PESecInfo.exe filename")
	printf("\n[?] Additional Parameters")
	printf("\n\t-d aslr : Disable ASLR")
	printf("\n\t-d dep  : Disable DEP")
	printf("\n\t-e aslr : Enable ASLR")
	printf("\n\t-e dep  : Enable DEP\n")
	invoke ExitProcess,-1

Begin:
	invoke MapAndLoad, addr buf, NULL, addr PE, NULL, NULL 	
	.if eax != NULL
		invoke checkPE, PE	
		.if eax != NULL
			invoke checkArch, PE
			
			printf("[+] ASLR       : ") 
			invoke isDynamicBase2, PE  
			.if eax != NULL
				printf("True\n")
			.else
				printf("False\n")		
			.endif	
			
			printf("[+] DEP        : ") 
			invoke isDEP,PE
			.if eax != NULL
				printf("True\n")
			.else
				printf("False\n")		
			.endif	
			
			printf("[+] CFG        : ") 
			invoke isCFG,PE
			.if eax != NULL
				printf("True\n")
			.else
				printf("False\n")		
			.endif	
			
			printf("[+] Isolation  : ") 
			invoke isIsolation,PE
			.if eax != NULL
				printf("True\n")
			.else
				printf("False\n")		
			.endif
			
		.else
			invoke crt_printf, addr crlf
			invoke crt_printf, chr$("[!] This is not a valid PE")
			invoke crt_printf, addr crlf
		.endif	
	.else
		invoke crt_printf, addr crlf
		invoke crt_printf, chr$("[!] This is not a valid PE")
		invoke crt_printf, addr crlf
	.endif
Exit::
	invoke UnMapAndLoad, addr PE
	invoke ExitProcess, 0	
start endp	


checkPE proc PE:LOADED_IMAGE
	mov ebx, PE.MappedAddress
	assume ebx:ptr IMAGE_DOS_HEADER
	.if [ebx].e_magic == IMAGE_DOS_SIGNATURE
		add ebx, [ebx].e_lfanew
		assume ebx:ptr IMAGE_NT_HEADERS32
		.if [ebx].Signature == IMAGE_NT_SIGNATURE
			mov eax, TRUE
			ret
		.else
			mov eax, FALSE
			ret
		.endif
	.else
		mov eax, FALSE
		ret 
		
	.endif
checkPE EndP

checkArch proc PE:LOADED_IMAGE
	mov ebx, PE.FileHeader
	printf("[+] Arch       : ") 
	.if [ebx].IMAGE_NT_HEADERS32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		printf("32-bit\n")
		ret
	.elseif [ebx].IMAGE_NT_HEADERS32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
		printf("64-bit\n")
		ret
	.elseif [ebx].IMAGE_NT_HEADERS32.OptionalHeader.Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC
		printf("Rom Image\n")
		ret
	.else
		printf("Unknown\n")
		ret		
	.endif
checkArch EndP


isDynamicBase2 proc PE:LOADED_IMAGE
	mov edi, PE.FileHeader
	mov edi, dword ptr [edi].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics 
	and edi, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	.if edi == IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		mov eax, TRUE
		ret
	.else
		mov eax, FALSE
		ret
	.endif		
isDynamicBase2 EndP


isDEP proc PE:LOADED_IMAGE
	mov ebx, PE.FileHeader
	mov ebx, dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics
	and ebx, IMAGE_DLLCHARACTERISTICS_NX_COMPAT	
	.if	ebx == IMAGE_DLLCHARACTERISTICS_NX_COMPAT	
		mov eax, TRUE
		ret
	.else
		mov eax, FALSE
		ret
	.endif
isDEP EndP


isCFG proc PE:LOADED_IMAGE
	mov ebx, PE.FileHeader
	mov ebx, dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics
	and ebx, 4000h	
	.if	ebx == 4000h	
		mov eax, TRUE
		ret
	.else
		mov eax, FALSE
		ret
	.endif
	mov ebx, PE.FileHeader

isCFG EndP


isIsolation proc PE:LOADED_IMAGE
	mov ebx, PE.FileHeader
	mov ebx, dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics
	and ebx, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION	
	.if	ebx != IMAGE_DLLCHARACTERISTICS_NO_ISOLATION	
		mov eax, TRUE
		ret
	.else
		mov eax, FALSE
		ret
	.endif
isIsolation EndP


disableAslr proc PE:LOADED_IMAGE
	invoke isDynamicBase2, PE
	.if !eax 
		invoke crt_printf, addr crlf 
		invoke crt_printf, chr$("[!] ASLR is already Disabled")
		invoke crt_printf, addr crlf 
		jmp Exit
	.else
	xor edx, edx
	xor eax, eax
	mov ebx, PE.FileHeader
	mov eax, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	not eax
	and dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics, eax
	.endif
	printf("\n[*] ASLR Disabled\n")
	ret
disableAslr EndP


enableAslr proc PE:LOADED_IMAGE
	invoke isDynamicBase2, PE
	.if eax != NULL
		invoke crt_printf, addr crlf 
		invoke crt_printf, chr$("[!] ASLR is already Enabled")
		invoke crt_printf, addr crlf 
		jmp Exit
	.else
	mov ebx, PE.FileHeader
	or dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	.endif
	printf("\n[*] ASLR Enabled\n")
	ret
enableAslr EndP

disableDep proc PE:LOADED_IMAGE
	invoke isDEP, PE
	.if eax == NULL
		invoke crt_printf, addr crlf 
		invoke crt_printf, chr$("[!] DEP is already Disabled")
		invoke crt_printf, addr crlf 
		jmp Exit
	.else
	xor edx, edx
	xor eax, eax
	mov ebx, PE.FileHeader
	mov eax, IMAGE_DLLCHARACTERISTICS_NX_COMPAT
	not eax
	and dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics, eax
	.endif
	printf("\n[*] DEP Disabled\n")
	ret
disableDep EndP

enableDep proc PE:LOADED_IMAGE
	invoke isDEP, PE
	.if eax != NULL
		invoke crt_printf, addr crlf 
		invoke crt_printf, chr$("[!] DEP is already Enabled")
		invoke crt_printf, addr crlf 
		jmp Exit
	.else
	mov ebx, PE.FileHeader
	or dword ptr [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics, IMAGE_DLLCHARACTERISTICS_NX_COMPAT
	.endif
	printf("\n[*] DEP Enabled\n")
	ret
enableDep EndP

end start
