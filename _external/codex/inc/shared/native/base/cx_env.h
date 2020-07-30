/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

//
// Environment detection for avoiding endless repetitive (and possibly wrong/incomplete) #if in subsequent code
//
// Defined symbols:
// - CX_COMPILER, CX_MSVC/CX_CLANG/CX_GNUC
// - CX_ARCH, CX_ARCH32/CX_ARCH64
// - CX_OS, CX_UNIX/CX_WINDOWS

#ifndef _CX_ENV_H_
#define _CX_ENV_H_


//
// Detect compiler and define CX_COMPILER, CX_MSVC/CX_CLANG/CX_GNUC
//

#ifdef _MSC_VER
#define CX_MSVC
#define CX_COMPILER MSVC
#else
#ifdef __clang__
#define CX_CLANG
#define CX_COMPILER CLANG
#else
#ifdef __GNUC__
#define CX_GNUC
#define CX_COMPILER GNUC
#endif
#endif
#endif

#ifndef CX_COMPILER
#error "Unsupported compiler"
#endif


//
// Detect the C standard supported by the compiler and define CX_CSTANDARD, CX_STDC89, CX_STDC90, CX_STDC99, CX_STDC11
//

#ifdef _MSC_VER
#if _MSC_VER >= 1200
#define CX_STDC89
#define CX_STDC90
#endif
#if _MSC_VER >= 1700
#define CX_STDC99
#endif
#else
#if defined(CX_CLANG) || defined(CX_GNUC)
#ifdef __STDC__
#define CX_STDC89
#define CX_STDC90
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 199901L
#define CX_STDC99
#endif
#if __STDC_VERSION__ >= 201112L
#define CX_STDC11
#endif
#endif
#endif
#endif
#endif


#ifdef CX_STDC11
#define CX_CSTANDARD 2011L
#else
#ifdef CX_STDC99
#define CX_CSTANDARD 1999L
#else
#ifdef CX_STDC90
#define CX_CSTANDARD 1990L
#else
#ifdef CX_STDC89
#define CX_CSTANDARD 1989L
#endif
#endif
#endif
#endif


#ifndef CX_CSTANDARD
#error "Unsupported compiler version"
#endif


//
// Detect the architecture by probing compiler-defined symbols (for the above compiler list) => CX_ARCH, CX_ARCH32/CX_ARCH64
//
#ifndef _M_X64
#ifndef _M_AMD64
#ifndef __amd64__
#ifndef __amd64
#ifndef __x86_64__
#ifndef __x86_64
#ifndef __LP64__
#define CX_ARCH32
#define CX_ARCH 32
#endif
#endif
#endif
#endif
#endif
#endif
#endif


#ifndef CX_ARCH32
#define CX_ARCH64
#define CX_ARCH 64
#endif




//
// Identify the operating system => CX_WINDOWS vs CX_UNIX
//
#ifdef __unix__
#define CX_UNIX
#else
#ifdef __unix
#define CX_UNIX
#else
#ifdef _WIN32
#define CX_WINDOWS
#else
#ifdef _WIN64
#define CX_WINDOWS
#endif
#endif
#endif
#endif

#ifdef CX_UNIX
#define CX_OS UNIX
#endif

#ifdef CX_WINDOWS
#define CX_OS WINDOWS
#endif

#ifndef CX_OS
#error "Unknown operating system!"
#endif


//
// Identify MINGW and CYGWIN
//
#if defined(__MINGW32__) || defined(__MINGW64__)
#define CX_MINGW
#endif

#ifdef __CYGWIN__
#define CX_CYGWIN
#endif


//
// COMPILER ABSTRACTION -- MOVE TO DEDICATED FILE!!
//
#ifndef CX_MSVC

#ifndef CX_MINGW
#ifdef CX_ARCH64
#define __cdecl
#else
#define __cdecl             __attribute__((cdecl))
#endif

#define __stdcall           __attribute__((stdcall))
#endif // CX_CYGWIN

#define __forceinline       __attribute__((always_inline)) inline

#endif


//
// BUILD TYPE/CONFIGURATION => CX_DEBUG_BUILD, CX_RELEASE_BUILD
//
#if !defined(CX_DEBUG_BUILD) && !defined(CX_RELEASE_BUILD)

#if defined(_DEBUG) || defined(_DBG) || defined (DEBUG) || defined(DBG)
#define CX_DEBUG_BUILD
#endif
#if defined(_RELEASE) || defined (_NDEBUG) || defined(RELEASE) || defined (NDEBUG)
#define CX_RELEASE_BUILD
#endif

#endif

#if defined(CX_DEBUG_BUILD) && defined(CX_RELEASE_BUILD)
#error "ERROR: Both debug and release build type/configuration options were inferred"
#endif

#if !defined(CX_DEBUG_BUILD) && !defined(CX_RELEASE_BUILD)
#ifndef CX_PROJECT_HAS_NO_CONFIGURATION
#error "ERROR: Cannot deduce configuration (CX_DEBUG_BUILD vs CX_RELEASE_BUILD), your project doesn't define any of _DEBUG/DEBUG/DBG or _RELEASE/RELEASE/_NDEBUG/NDEBUG"
#endif
#endif

#endif // _CX_ENV_H_
