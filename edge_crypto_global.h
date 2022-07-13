#ifndef __EDGE_GLOBAL_H__
#define __EDGE_GLOBAL_H__

#if defined(_WIN32)
    #include <Windows.h>
    #include <ctype.h>
    typedef unsigned _int64 UINT64;
#else /* POSIX */
    #include <sys/types.h>
    typedef unsigned long long UINT64;
#endif

#if defined(_MSC_VER)
#define EDGE_PATH_SEP                  '\\'
#else
#define EDGE_PATH_SEP                  '/'
#endif

#ifndef EXTERN_C
#if defined(__cplusplus)
#define EXTERN_C extern "C" 
#else
#define EXTERN_C extern 
#endif
#endif /* EXTERN_C */

#if !defined(__cplusplus) && !defined(__AP_HAS_BOOLEAN__) \
    && !defined(__bool_true_false_are_defined)
#define __AP_HAS_BOOLEAN__
typedef enum {
    false,
    true
} bool;
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#include <basetsd.h>
#if (_MSC_VER <= 1200)
typedef   signed short  int16_t;
typedef unsigned short uint16_t;
#else
typedef  INT16  int16_t;
typedef  UINT8  uint8_t;
typedef UINT16 uint16_t;
#endif
typedef  INT32  int32_t;
typedef  INT64  int64_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#else
#include <inttypes.h>

#if defined(LINUX) || defined(_LINUX)
#if defined(__aarch64__)
/* glibc 2.17 is the first glibc version that support aarch64
*               however memcpy is not versioned for aarch64 */
#define GLIBC_COMPAT_SYMBOL(FFF)
#elif defined(__arm__)
#define GLIBC_COMPAT_SYMBOL(FFF) __asm__(".symver " #FFF "," #FFF "@GLIBC_2.4");
#elif defined(__amd64__)
#define GLIBC_COMPAT_SYMBOL(FFF) __asm__(".symver " #FFF "," #FFF "@GLIBC_2.2.5");
#else
#define GLIBC_COMPAT_SYMBOL(FFF) __asm__(".symver " #FFF "," #FFF "@GLIBC_2.0");
#endif /*__amd64__*/
GLIBC_COMPAT_SYMBOL (memcpy);
GLIBC_COMPAT_SYMBOL (calloc);
GLIBC_COMPAT_SYMBOL (free);
GLIBC_COMPAT_SYMBOL (memset);
GLIBC_COMPAT_SYMBOL (setenv);
#endif

#endif /* _MSC_VER && !EFIX64 && !EFI32 */

#if defined(__GNUC__)       /* GNU Compiler */
#define EDGE_EXPORT EXTERN_C __attribute__((__visibility__("default")))
#if defined(CMVP_STATE_TEST)
#define EDGE_LOCAL EXTERN_C __attribute__((__visibility__("default")))
#else
#define EDGE_LOCAL EXTERN_C __attribute__((__visibility__("hidden")))
#endif
#elif defined(_MSC_VER)     /* MS-Windows */
#define EDGE_EXPORT EXTERN_C __declspec(dllexport)
#if defined(CMVP_STATE_TEST)
#define EDGE_LOCAL  EXTERN_C __declspec(dllexport)
#else
#define EDGE_LOCAL  EXTERN_C
#endif
#else                       /* Other Unix */
#define EDGE_EXPORT  EXTERN_C
#define EDGE_LOCAL  EXTERN_C
#endif

#endif /* _EDGE_GLOBAL_H_ */
