#pragma once

// Ver: http://powerofcommunity.net/poc2007/amesianx.pdf

#define DELEGATOR_ENTRY_POINTS(n) \
    static void __declspec(naked) del_##n(void) { \
        __asm push (n*4) \
        __asm jmp delegate \
    } \
    static void __declspec(naked) del2_##n(void) { \
        __asm push (n*4) \
        __asm jmp delegateAndPostprocess \
    }

static void __declspec(naked) delegate() {
    // TODO
}

static void delegateAndPostprocess() noexcept;

#pragma warning(push)
#pragma warning(disable: 4505)

#define FAKE_VTBL_MAX_ENTRIES 32

DELEGATOR_ENTRY_POINTS(0)
DELEGATOR_ENTRY_POINTS(1)
DELEGATOR_ENTRY_POINTS(2)
DELEGATOR_ENTRY_POINTS(3)
DELEGATOR_ENTRY_POINTS(4)
DELEGATOR_ENTRY_POINTS(5)
DELEGATOR_ENTRY_POINTS(6)
DELEGATOR_ENTRY_POINTS(7)
DELEGATOR_ENTRY_POINTS(8)
DELEGATOR_ENTRY_POINTS(9)
DELEGATOR_ENTRY_POINTS(10)
DELEGATOR_ENTRY_POINTS(11)
DELEGATOR_ENTRY_POINTS(12)
DELEGATOR_ENTRY_POINTS(13)
DELEGATOR_ENTRY_POINTS(14)
DELEGATOR_ENTRY_POINTS(15)
DELEGATOR_ENTRY_POINTS(16)
DELEGATOR_ENTRY_POINTS(17)
DELEGATOR_ENTRY_POINTS(18)
DELEGATOR_ENTRY_POINTS(19)
DELEGATOR_ENTRY_POINTS(20)
DELEGATOR_ENTRY_POINTS(21)
DELEGATOR_ENTRY_POINTS(22)
DELEGATOR_ENTRY_POINTS(23)
DELEGATOR_ENTRY_POINTS(24)
DELEGATOR_ENTRY_POINTS(25)
DELEGATOR_ENTRY_POINTS(26)
DELEGATOR_ENTRY_POINTS(27)
DELEGATOR_ENTRY_POINTS(28)
DELEGATOR_ENTRY_POINTS(29)
DELEGATOR_ENTRY_POINTS(30)
DELEGATOR_ENTRY_POINTS(31)

#pragma warning( pop )

static void * fake_vtbl[FAKE_VTBL_MAX_ENTRIES] = {
    del2_0,
    del2_1,
    del2_2,
    del2_3,
    del2_4,
    del2_5,
    del2_6,
    del2_7,
    del2_8,
    del2_9,
    del2_10,
    del2_11,
    del2_12,
    del2_13,
    del2_14,
    del2_15,
    del2_16,
    del2_17,
    del2_18,
    del2_19,
    del2_20,
    del2_21,
    del2_22,
    del2_23,
    del2_24,
    del2_25,
    del2_26,
    del2_27,
    del2_28,
    del2_29,
    del2_30,
    del2_31
};

static void * real_vtbl[FAKE_VTBL_MAX_ENTRIES] = { nullptr };


// forward-declaration
static void __declspec(naked) delegateAndPostprocess() noexcept {

#define MHC_USE_DELEGATE_HOOK_CODE 1
#define MHC_TRACK_STACK 1
#if !MHC_USE_DELEGATE_HOOK_CODE
#define argVTblOffset ebp +  4
#define argRetAddr    ebp +  8
#define argThis       ebp + 12

    __asm {
        push ebp
        mov  ebp, esp // stack frame
        push ecx
        push edx
    }
    // call preprocess2
    __asm {
        mov  ecx, [argVTblOffset]

        lea  eax, [argThis] // address of 'this' location (1st argument)
        push eax
        push ecx
        mov  edx, [argRetAddr]
        push edx
        add  ecx, offset real_vtbl
        mov  eax, dword ptr [ecx] // address of vtable function
        push eax // should be saved real address
        call preprocess2
    }
    // call original virtual function
    __asm {
        mov  eax, offset real_vtbl
        add  eax, [argVTblOffset] // vtbl index (already times four)
        mov  eax, [eax] // address of vtable function

        pop  ecx
        pop  edx
        pop  ebp

        mov  [esp], eax // this overwrites the vtbl index, but we don't care, we are jumping to the original method
        ret
    }
#undef argVTblOffset
#undef argRetAddr
#undef argThis

#else // !MHC_USE_DELEGATE_HOOK_CODE
    /// ESP points always to the LAST VALUE STORED
    __asm {
        // get the vtbl index
        pop  eax			// eax = vtbl index (in bytes)
        sub  esp, 8
        push eax
        push ebp			// set up simple stack frame
        mov  ebp, esp

        // ebp+4  = local variable: vtbl offset (in bytes)
        // ebp+8  = local variable: result of context allocation
        // ebp+12 = local variable: address of inner's method
        //     IF TRACK_STACK, THERE IS ANOTHER LOCAL VARIABLE HERE!
        //     (THE ESP BEFORE CALLING THE FUNCTION, TO COMPARE WITH AFTER
        //      AND SEE HOW MANY PARAMETERS THE FUNCTION RECEIVES)
        // ebp+16 = retaddr
        // ebp+20 = this
        // ebp+24 = args

#if MHC_TRACK_STACK
        lea  eax, [esp + 12]
        push eax // original esp
#else
        push 0
#endif
        lea  eax, [ebp+24]	// eax = preprocess2( this, pReturnAddr, nVtblOffset, pArgs );
        push eax
        push [ebp+4]
        push [ebp+16]
        push [ebp+20]
        call preprocess2
        mov  [ebp+8], eax	// store result of context allocation

#if !MHC // this breaks since I have not implemented pInner
        mov  eax, [ebp+20]	// this = eax = pInner
        mov  eax, [eax+4]
        mov  [ebp+20], eax	

        mov  eax, [eax]		// store address of inner's virtual function
        add  eax, [ebp+4]
        mov  eax, [eax]		
        mov  [ebp+12], eax
#else // !MHC
        mov  eax, offset real_vtbl
        add  eax, [ebp+4] // vtbl index (already times four)
        mov  eax, [eax] // address of vtable function
        mov  [ebp+12], eax
#endif // !MHC

        pop  ebp			// tear down stack frame
        pop  eax			// discard vtbl offset

        pop  eax			// was context alloc successful?
        test eax, 1
        jnz allocSuccessful

        pop	 eax			// delegate without postprocessing
        jmp eax

    allocSuccessful:
        pop  eax
        add  esp, 4			// remove caller's return addr from stack and call inner
        call eax

        sub  esp, 4			// make room for original return addr
        push esp			// eax = postprocess( eax, stack_diff, ppReturnAddr )
#if MHC_TRACK_STACK
        push  esp
#else
        push  0
#endif
        push eax
        call postprocess

        ret
    }
#endif // !MHC_USE_DELEGATE_HOOK_CODE
}

#define USE_DETOURS 0

#if USE_DETOURS
#   define FIX_VTABLE(vtbl, i) _Print("vtbl[%d]  = %p\n", i, vtbl[i]); real_vtbl[i] = vtbl[i]; _Print("Attach: %d\n", DetourAttach(&real_vtbl[i] , fake_vtbl[i]));
#else // USE_DETOURS
    // do not do the trampoline thing, since you overwrite all reused functions in vtables
#   define FIX_VTABLE(vtbl, i) \
        do { \
            /* BUG: Do not patch twice!! Leads to the infinite loops... */ \
            if (vtbl[i] != fake_vtbl[i]) { \
                HANDLE process = ::GetCurrentProcess(); \
                DWORD protection = PAGE_READWRITE; \
                DWORD oldProtection; \
                real_vtbl[i] = vtbl[i]; /* save original value (to be called) */ \
                _Print("Real: %p - vtbl: %p\n", real_vtbl[i], vtbl[i]); \
                if ( ::VirtualProtectEx( process, &vtbl[i], sizeof(int), protection, &oldProtection ) ) \
                { \
                    vtbl[i] = fake_vtbl[i]; \
                    if ( ::VirtualProtectEx( process, &vtbl[i], sizeof(int), oldProtection, &oldProtection )) { \
                        _Print("Patched vtbl[%d]: %p -> %p\n", i, real_vtbl[i], fake_vtbl[i]); \
                    } \
                } \
            } else { \
                /* _Print("Already patched...\n"); */ \
            } \
        } while(0)
#endif // USE_DETOURS

typedef void *FuncPtr;

static UINT_PTR FuncRegion(FuncPtr f) {
    const UINT_PTR REG_MASK = 0xfff00000;
    return (UINT_PTR)f & REG_MASK;
}

VOID _Print(const CHAR *psz, ...);

void hackVtable(FuncPtr vtable[]) {
#if USE_DETOURS
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
#endif // USE_DETOURS

    FuncPtr QI = vtable[0];
    UINT_PTR QI_region = FuncRegion(QI); // we'll accept functions in the same "region" as QI

#if !MHC_TRACK_IUNK
    int i = 3;
#else // !MHC
    int i = 0;
#endif // !MHC
    for (; i < FAKE_VTBL_MAX_ENTRIES; i++) {
        FuncPtr thisFunc = vtable[i];
        if (FuncRegion(thisFunc) != QI_region) break;
        FIX_VTABLE(vtable, i);
    }

#if USE_DETOURS
    DetourTransactionCommit();
#endif // USE_DETOURS
}
