/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifdef crt_INC_SETTINGS_STRING_H
#include crt_INC_SETTINGS_STRING_H // define it to some .h file name/path if you want to provide settings
#endif


#ifndef _CRT_STRING_WRAPPER_
#define _CRT_STRING_WRAPPER_

#include "crt/crt_string.h"

#if ( !defined(CRT_SKIP_DECL_PWCHAR) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_PWCHAR))  )
#define PWCHAR                          CRT_PWCHAR
#endif

#if ( !defined(CRT_SKIP_DECL_WCHAR) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_WCHAR))  )
#define WCHAR                           CRT_WCHAR
#endif

#if ( !defined(CRT_SKIP_DECL_ISALPHA) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_ISALPHA))  )
#define isalpha                         crt_isalpha
#endif

#if ( !defined(CRT_SKIP_DECL_ISDIGIT) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_ISDIGIT))  )
#define isdigit                         crt_isdigit
#endif

#if ( !defined(CRT_SKIP_DECL_ISPRINT) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_ISPRINT))  )
#define isprint                         crt_isprint
#endif

#if ( !defined(CRT_SKIP_DECL_ISSPACE) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_ISSPACE))  )
#define isspace                         crt_isspace
#endif

#if ( !defined(CRT_SKIP_DECL_ISXDIGIT) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_ISXDIGIT))  )
#define isxdigit                        crt_isxdigit
#endif

#if ( !defined(CRT_SKIP_DECL_RPL_VSNPRINTF) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_RPL_VSNPRINTF))  )
#define rpl_vsnprintf                   crt_vsnprintf
#endif


#if ( !defined(CRT_SKIP_DECL_RPL_SNPRINTF) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_RPL_SNPRINTF))  )
#define rpl_snprintf                   crt_snprintf
#endif

#if ( !defined(CRT_SKIP_DECL_VSNPRINTF) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_VSNPRINTF))  )
#define vsnprintf                      crt_vsnprintf
#endif

#if ( !defined(CRT_SKIP_DECL_SNPRINTF) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_SNPRINTF))  )
#define snprintf                        crt_snprintf
#endif

#if ( !defined(CRT_SKIP_DECL_STRCAT) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCAT))  )
#define strcat                          crt_strcat
#endif

#if ( !defined(CRT_SKIP_DECL_STRCAT_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCAT_S))  )
#define strcat_s                        crt_strcat_s
#endif

#if ( !defined(CRT_SKIP_DECL_STRCHR) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCHR))  )
#define strchr                          crt_strchr
#endif

#if ( !defined(CRT_SKIP_DECL_STRCHR_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCHR_S))  )
#define strchr_s                        crt_strchr_s
#endif

#if ( !defined(CRT_SKIP_DECL_STRCMP) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCMP))  )
#define strcmp                          crt_strcmp
#endif

#if ( !defined(CRT_SKIP_DECL_STRCPY) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCPY))  )
#define strcpy                          crt_strcpy
#endif

#if ( !defined(CRT_SKIP_DECL_STRCPY_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRCPY_S))  )
#define strcpy_s                        crt_strcpy_s
#endif

#if ( !defined(CRT_SKIP_DECL_STREND) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STREND))  )
#define strend                          crt_strend
#endif

#if ( !defined(CRT_SKIP_DECL_STREND_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STREND_S))  )
#define strend_s                        crt_strend_s
#endif

#if ( !defined(CRT_SKIP_DECL_STRICMP) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRICMP))  )
#define stricmp                         crt_stricmp
#endif

#if ( !defined(CRT_SKIP_DECL_STRLEN) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRLEN))  )
#define strlen                          crt_strlen
#endif

#if ( !defined(CRT_SKIP_DECL_STRLEN_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRLEN_S))  )
#define strlen_s                        crt_strlen_s
#endif

#if ( !defined(CRT_SKIP_DECL_STRNCAT) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRNCAT))  )
#define strncat                         crt_strncat
#endif

#if ( !defined(CRT_SKIP_DECL_STRNCMP) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRNCMP))  )
#define strncmp                         crt_strncmp
#endif

#if ( !defined(CRT_SKIP_DECL_STRNCPY) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRNCPY))  )
#define strncpy                         crt_strncpy
#endif

#if ( !defined(CRT_SKIP_DECL_STRNICMP) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRNICMP))  )
#define strnicmp                        crt_strnicmp
#endif

#if ( !defined(CRT_SKIP_DECL_STRRCHR) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRRCHR))  )
#define strrchr                         crt_strrchr
#endif

#if ( !defined(CRT_SKIP_DECL_STRRCHR_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRRCHR_S))  )
#define strrchr_s                       crt_strrchr_s
#endif

#if ( !defined(CRT_SKIP_DECL_STRSTR) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRSTR))  )
#define strstr                          crt_strstr
#endif

#if ( !defined(CRT_SKIP_DECL_STRSTR_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRSTR_S))  )
#define strstr_s                        crt_strstr_s
#endif

#if ( !defined(CRT_SKIP_DECL_STRTRUNCATE) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_STRTRUNCATE))  )
#define strtruncate                     crt_strtruncate
#endif

#if ( !defined(CRT_SKIP_DECL_TOLOWER) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_TOLOWER))  )
#define tolower                         crt_tolower
#endif

#if ( !defined(CRT_SKIP_DECL_TOUPPER) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_TOUPPER))  )
#define toupper                         crt_toupper
#endif

#if ( !defined(CRT_SKIP_DECL_WSTRLEN) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_WSTRLEN))  )
#define wstrlen                         crt_wstrlen
#endif

#if ( !defined(CRT_SKIP_DECL_WSTRLEN_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_WSTRLEN_S))  )
#define wstrlen_s                       crt_wstrlen_s
#endif

#if ( !defined(CRT_SKIP_DECL_WSTRTRUNCATE) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_WSTRTRUNCATE))  )
#define wstrtruncate                    crt_wstrtruncate
#endif

#if ( !defined(CRT_SKIP_DECL_WSTRSTR_S) && (!defined(CRT_DEFAULT_SKIP_STRING_H_DECL) || defined(CRT_WANT_DECL_WSTRSTR_S)))
#define wstrstr_s                       crt_wstrstr_s
#endif


#endif //_CRT_STRING_WRAPPER_
