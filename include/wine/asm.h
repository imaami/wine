/*
 * Inline assembly support
 *
 * Copyright 2019 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_WINE_ASM_H
#define __WINE_WINE_ASM_H

#if defined(__APPLE__) || (defined(_WIN32) && defined(__i386__))
# define __ASM_NAME(name) "_" name
#else
# define __ASM_NAME(name) name
#endif

#if defined(_WIN32) && defined(__i386__)
# define __ASM_STDCALL(args) "@" #args
#else
# define __ASM_STDCALL(args) ""
#endif

#ifdef __GCC_HAVE_DWARF2_CFI_ASM
# define __ASM_CFI(str) str
#else
# define __ASM_CFI(str)
#endif

#ifdef _WIN32
# define __ASM_FUNC_TYPE(name) ".def " name "; .scl 2; .type 32; .endef"
#elif defined(__APPLE__)
# define __ASM_FUNC_TYPE(name) ""
#elif defined(__arm__) || defined(__arm64__)
# define __ASM_FUNC_TYPE(name) ".type " name ",%function"
#else
# define __ASM_FUNC_TYPE(name) ".type " name ",@function"
#endif

#ifdef __GNUC__
# define __ASM_DEFINE_FUNC(name,code) \
    asm(".text\n\t.align 4\n\t.globl " name "\n\t" __ASM_FUNC_TYPE(name) "\n" name ":\n\t" \
        __ASM_CFI(".cfi_startproc\n\t") code __ASM_CFI("\n\t.cfi_endproc") );
#else
# define __ASM_DEFINE_FUNC(name,code) void __asm_dummy_##__LINE__(void) { \
    asm(".text\n\t.align 4\n\t.globl " name "\n\t" __ASM_FUNC_TYPE(name) "\n" name ":\n\t" \
        __ASM_CFI(".cfi_startproc\n\t") code __ASM_CFI("\n\t.cfi_endproc") ); }
#endif

#define __ASM_GLOBAL_FUNC(name,code) __ASM_DEFINE_FUNC(__ASM_NAME(#name),code)

#define __ASM_STDCALL_FUNC(name,args,code) __ASM_DEFINE_FUNC(__ASM_NAME(#name) __ASM_STDCALL(args),code)

/* fastcall support */

#if defined(__i386__) && !defined(_WIN32)

# define DEFINE_FASTCALL1_WRAPPER(func) \
    __ASM_STDCALL_FUNC( __fastcall_ ## func, 4, \
                        "popl %eax\n\t"  \
                        "pushl %ecx\n\t" \
                        "pushl %eax\n\t" \
                        "jmp " __ASM_NAME(#func) __ASM_STDCALL(4) )
# define DEFINE_FASTCALL_WRAPPER(func,args) \
    __ASM_STDCALL_FUNC( __fastcall_ ## func, args, \
                        "popl %eax\n\t"  \
                        "pushl %edx\n\t" \
                        "pushl %ecx\n\t" \
                        "pushl %eax\n\t" \
                        "jmp " __ASM_NAME(#func) __ASM_STDCALL(args) )

#else  /* __i386__ */

# define DEFINE_FASTCALL1_WRAPPER(func) /* nothing */
# define DEFINE_FASTCALL_WRAPPER(func,args) /* nothing */

#endif  /* __i386__ */

/* thiscall support */

#undef __thiscall
#define __thiscall __stdcall

#ifdef __i386__

# ifdef _MSC_VER
#  define DEFINE_THISCALL_WRAPPER(func,args) \
    __declspec(naked) HRESULT __thiscall_##func(void) \
    { __asm { \
        pop eax \
        push ecx \
        push eax \
        jmp func \
    } }
# else  /* _MSC_VER */
#  define DEFINE_THISCALL_WRAPPER(func,args) \
    extern void __thiscall_ ## func(void);  \
    __ASM_GLOBAL_FUNC( __thiscall_ ## func, \
                       "popl %eax\n\t"  \
                       "pushl %ecx\n\t" \
                       "pushl %eax\n\t" \
                       "jmp " __ASM_NAME(#func) __ASM_STDCALL(args) )
# endif  /* _MSC_VER */

# define THISCALL(func) (void *)__thiscall_ ## func
# define THISCALL_NAME(func) __ASM_NAME("__thiscall_" #func)

#else  /* __i386__ */

# define DEFINE_THISCALL_WRAPPER(func,args) /* nothing */
# define THISCALL(func) func
# define THISCALL_NAME(func) __ASM_NAME(#func)

#endif  /* __i386__ */

#endif  /* __WINE_WINE_ASM_H */
