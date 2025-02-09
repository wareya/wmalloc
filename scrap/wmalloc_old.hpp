#ifndef _WALLOC_OS_HPP
#define _WALLOC_OS_HPP

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include <atomic>

#ifndef WALLOC_CUSTOMHEADER

#ifdef WALLOC_CAS16
struct WAllocHeaderTagPiece
{
    __attribute__((__aligned__(16))) size_t ** next;
    size_t tag;
};
#endif
struct WAllocHeader
{
    size_t size;
#ifdef WALLOC_CAS16
    size_t pad1;
#endif
    size_t ** next;
#ifdef WALLOC_CAS16
    size_t tag;
#endif
};
#endif

#ifndef WALLOC_CUSTOMALIGN
#define WALLOC_CUSTOMALIGN 16
#endif

#ifndef WALLOC_PAD
#define WALLOC_PAD 0
#endif

// WALLOC_SYS_MALLOC

// WALLOC_NOHEADERNOPOISON
// WALLOC_CACHEHINT
// WALLOC_NOZERO
// WALLOC_LINUX_NO_PROT_NONE
// WALLOC_LINUX_NO_MADV_FREE

#ifdef WALLOC_MAXIMUM_FAST
#define WALLOC_NOZERO
#define WALLOC_LINUX_NO_PROT_NONE
#define WALLOC_LINUX_NO_MADV_FREE
#endif

static size_t _walloc_os_page_size = 0;
static size_t _walloc_os_page_size_log2 = 0;
static char * _walloc_heap_base = 0;
static std::atomic<char *> _walloc_heap_cur = 0;
static std::atomic<char *> _walloc_heap_top = 0;
#ifdef WALLOC_CAS16
static std::atomic<WAllocHeaderTagPiece> _walloc_heap_free[64] = {};
#else
static std::atomic<char *> _walloc_heap_free[64] = {};
#endif
struct CharP { char * p; };

typedef WAllocHeader * WAllocHeaderPtr;
#define WALLOC_OFFS (WALLOC_CUSTOMALIGN > sizeof(WAllocHeader) ? WALLOC_CUSTOMALIGN : sizeof(WAllocHeader))

#if (__has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__))
#include <sanitizer/asan_interface.h>
void _walloc_asan_poison(void * a, size_t n)
{
    #ifndef WALLOC_NOHEADERNOPOISON
    if (a) ASAN_POISON_MEMORY_REGION(a, n);
    #endif
}
void _walloc_asan_unpoison(void * a, size_t n) { if (a) ASAN_UNPOISON_MEMORY_REGION(a, n); }
#else
void _walloc_asan_unpoison(void *, size_t) { }
void _walloc_asan_poison(void *, size_t) { }
#endif

inline static void _walloc_rawmal_inner_pages(char ** p, size_t * s)
{
    char * p2 = *p;
    char * end = *p + *s;
    p2 += _walloc_os_page_size-1;
    p2 = (char *)(size_t(p2) >> _walloc_os_page_size_log2);
    p2 = (char *)(size_t(p2) << _walloc_os_page_size_log2);
    *p = 0;
    *s = 0;
    if (end < p2 + _walloc_os_page_size)
        return;
    size_t byte_count = end-p2;
    size_t page_count = byte_count >> _walloc_os_page_size_log2;
    *p = p2;
    *s = page_count << _walloc_os_page_size_log2;
}

static inline void _walloc_commit(char * p, size_t n);
static inline void _walloc_decommit(char * p, size_t n);
static inline void _walloc_recommit(char * p, size_t n);
static inline bool _malloc_commit_needed();
extern "C" void * _walloc_raw_malloc(size_t n);
extern "C" void * _walloc_raw_calloc(size_t c, size_t n);
extern "C" void _walloc_raw_free(void * p);

#include <thread>

struct WMallocSpinLock
{
    std::atomic_flag locked = ATOMIC_FLAG_INIT;
    void lock()
    {
        if (!locked.test_and_set(std::memory_order_acq_rel))
            return;
        do {
            std::this_thread::yield();
        } while (locked.test_and_set(std::memory_order_acq_rel));
    }
    void unlock() { locked.clear(std::memory_order_release); }
};

//#include <mutex>
//static std::mutex _mtx;
static WMallocSpinLock _mtx;

extern "C" void * _walloc_raw_malloc(size_t n)
{
    #ifdef WALLOC_SYS_MALLOC
    return malloc(n);
    
    #else
    
    if (!n || n > 0x100000000000) return 0;
    if (n < 8) n = 8;
    //n = std::bit_ceil(n);
    
    n = 1ULL << (64-__builtin_clzll(n-1));
    int bin = __builtin_ctzll(n);
    
    //std::atomic_thread_fence(std::memory_order_seq_cst);
    
    // any data race on this read will merely result in a missed freelist reusage
    // also, note that WAllocHeaderTagPiece is a 2-word struct of pointer and tag
    #ifdef WALLOC_CAS16
    WAllocHeaderTagPiece next = _walloc_heap_free[bin].load(std::memory_order_acquire);
    if (next.next)
    {
    #else
    char * maybe = _walloc_heap_free[bin].load(std::memory_order_acquire);
    if (maybe)
    {
    #endif
        #ifdef WALLOC_CAS16
            while (next.next && !_walloc_heap_free[bin].compare_exchange_strong(
                next,
                *(WAllocHeaderTagPiece*)&(WAllocHeaderPtr(next.next)->next),
                std::memory_order_release, std::memory_order_relaxed))
            { 
                #ifdef WALLOC_CAS16_LAZY
                std::this_thread::yield(); // makes it faster and more stable
                #endif
            }
            char * p = (char *)next.next;
        #else
            #ifdef WALLOC_LOCK
            _mtx.lock();
            char * p = _walloc_heap_free[bin].load(std::memory_order_acquire);
            if (p) _walloc_heap_free[bin].store((char*)WAllocHeaderPtr(p)->next, std::memory_order_release);
            _mtx.unlock();
            #else
            char * p = maybe;
            while (p && !_walloc_heap_free[bin].compare_exchange_weak(p, (char*)WAllocHeaderPtr(p)->next, std::memory_order_release, std::memory_order_relaxed))
            { }
            #endif
        #endif
        
        if (p)
        {
            char * p2 = p+WALLOC_OFFS;
            size_t s = n;
            _walloc_rawmal_inner_pages(&p2, &s);
            _walloc_recommit(p2, s);
            
            #ifndef WALLOC_NOZERO
            memset(p, 0, n + WALLOC_OFFS);
            #endif
            
            //assert(!WAllocHeaderPtr(p)->size);
            WAllocHeaderPtr(p)->size = n;
            WAllocHeaderPtr(p)->next = 0;
            #ifdef WALLOC_CAS16
            WAllocHeaderPtr(p)->tag += 1;
            #endif
            
            return (void *)(p+WALLOC_OFFS);
        }
    }
    
    // n is basic allocation size (rounded up to a power of 2)
    auto n2 = n + WALLOC_OFFS + WALLOC_PAD;
    n2 = (n2+(WALLOC_CUSTOMALIGN-1)) & ~(WALLOC_CUSTOMALIGN-1);
    #ifdef WALLOC_CACHEHINT
    n2 = (n2+(WALLOC_CACHEHINT-1)) & ~(WALLOC_CACHEHINT-1);
    #endif
    char * p = _walloc_heap_cur.fetch_add(n2);
    
    if (_malloc_commit_needed())
    {
        char * top = _walloc_heap_top.load(std::memory_order_acquire);
        while (!top)
            top = _walloc_heap_top.load(std::memory_order_acquire);
        assert(top);
        
        ptrdiff_t over = p + n2 - top;
        if (over > 0)
        {
            over = (over + (_walloc_os_page_size - 1)) & ~(_walloc_os_page_size-1);
            char * desired = 0; // use a value of 0 as a spinlock
            do {
                char * oldtop = top;
                if (_walloc_heap_top.compare_exchange_weak(top, desired, std::memory_order_release, std::memory_order_relaxed))
                {
                    if (over > 0)
                        _walloc_commit(oldtop, over);
                    _walloc_heap_top.store(oldtop + over, std::memory_order_release);
                    break;
                }
                while (!top)
                    top = _walloc_heap_top.load(std::memory_order_acquire);
                
                over = p + n2 - top;
                if (over < 0) break;
                over = (over + (_walloc_os_page_size - 1)) & ~(_walloc_os_page_size-1);
            } while (true);
        }
    }
    
    //assert(!WAllocHeaderPtr(p)->size);
    WAllocHeaderPtr(p)->size = n;
    //assert(WAllocHeaderPtr(p)->size);
    WAllocHeaderPtr(p)->next = 0;
    #ifdef WALLOC_CAS16
    WAllocHeaderPtr(p)->tag = 0;
    #endif
    
    //std::atomic_thread_fence(std::memory_order_seq_cst);
    
    return (void *)(p+WALLOC_OFFS);
    #endif
}
extern "C" void * _walloc_raw_calloc(size_t c, size_t n)
{
    #ifdef WALLOC_SYS_MALLOC
    return calloc(c, n);
    
    #else
    
    auto r = _walloc_raw_malloc(c*n);
    return r;
    #endif
}
extern "C" void * _walloc_raw_realloc(void * p, size_t n)
{
    #ifdef WALLOC_SYS_MALLOC
    return realloc(p, n);
    
    #else
    auto r = _walloc_raw_malloc(n);
    if (!p) return r;
    char * _p = ((char *)p)-WALLOC_OFFS;
    size_t s = WAllocHeaderPtr(_p)->size;
    assert(WAllocHeaderPtr(_p)->size);
    
    s <<= 8;
    s >>= 8;
    if (s < n) n = s;
    memcpy(r, p, n);
    return r;
    #endif
}

extern "C" void _walloc_raw_free(void * _p)
{
    #ifdef WALLOC_SYS_MALLOC
    return free(_p);
    
    #else
    
    if (!_p) return;
    char * p = ((char *)_p)-WALLOC_OFFS;
    
    //if (!WAllocHeaderPtr(p)->size) return; // double free
    //assert(WAllocHeaderPtr(p)->size); // double free
    
    #ifdef WALLOC_CAS16
        // the top 16 bits of the tag can contain user data
        WAllocHeaderPtr(p)->tag <<= 16;
        WAllocHeaderPtr(p)->tag >>= 16;
    #endif
    
    size_t n = WAllocHeaderPtr(p)->size;
    WAllocHeaderPtr(p)->size = 0;
    n <<= 8;
    n >>= 8;
    //n = std::bit_ceil(n);
    n = 1ULL << (64-__builtin_clzll(n-1));
    int bin = __builtin_ctzll(n);
    
    _walloc_decommit(p, n+WALLOC_OFFS);
    
    //std::atomic_thread_fence(std::memory_order_seq_cst);
    
    auto gp = WAllocHeaderPtr(p);
    #ifdef WALLOC_CAS16
        #if 1
        gp->tag += 1;
        #else
        auto piece = (WAllocHeaderTagPiece*)&(gp->next);
        WAllocHeaderTagPiece piece_new = std::atomic_ref(*piece).load(std::memory_order_acquire);
        piece_new.tag += 1;
        std::atomic_ref(*piece).store(piece_new, std::memory_order_release);
        #endif
        
        auto next = _walloc_heap_free[bin].load(std::memory_order_acquire);
        WAllocHeaderTagPiece otherwise;
        gp->next = next.next;
        otherwise = WAllocHeaderTagPiece{(size_t **)gp, gp->tag};
        while (!_walloc_heap_free[bin].compare_exchange_strong(next, otherwise, std::memory_order_release, std::memory_order_relaxed))
        {
            #ifdef WALLOC_CAS16_LAZY
            std::this_thread::yield();
            #endif
            gp->next = next.next;
            otherwise = WAllocHeaderTagPiece{(size_t **)gp, gp->tag};
        }
    #else
        #ifdef WALLOC_LOCK
        _mtx.lock();
        gp->next = (size_t **)_walloc_heap_free[bin].load(std::memory_order_acquire);
        _walloc_heap_free[bin].store((char *)gp, std::memory_order_release);
        _mtx.unlock();
        #else
        gp->next = (size_t **)_walloc_heap_free[bin].load(std::memory_order_acquire);
        while (!_walloc_heap_free[bin].compare_exchange_weak(*(char **)&gp->next, (char *)gp, std::memory_order_release, std::memory_order_relaxed))
        { }
        #endif
    #endif

    //printf("%p %zd\n", _walloc_heap_free[bin].load().next, _walloc_heap_free[bin].load().tag);
    
    //std::atomic_thread_fence(std::memory_order_seq_cst);
    
    #endif
}

#ifdef _WIN32

///////
/////// platform-specific Windows stuff ///////
///////

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#include <windows.h>
#include <psapi.h>

static inline CharP _walloc_os_init_heap()
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    _walloc_os_page_size = info.dwPageSize;
    _walloc_os_page_size_log2 = 64-__builtin_clzll(_walloc_os_page_size-1);
    // 16 TiB should be enough for anybody
    auto ret = (char *)VirtualAlloc(0, 0x100000000000, MEM_RESERVE, PAGE_READWRITE);
    assert(ret);
    _walloc_heap_base = ret;
    _walloc_heap_cur.store(ret);
    _walloc_heap_top.store(ret);
    //for (size_t i = 0; i < 64; i++)
    //    assert(_walloc_heap_free[i] == 0);
    #ifdef WALLOC_CAS16
    for (size_t i = 0; i < 64; i++)
        _walloc_heap_free[i].store({0, 0});
    #endif
    return CharP{ret};
}

#else // WIN32 -> LINUX

///////
/////// platform-specific Linux stuff ///////
///////

#include <sys/mman.h>
#include <linux/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <ucontext.h>

static inline CharP _walloc_os_init_heap()
{
    _walloc_os_page_size = (size_t)sysconf(_SC_PAGESIZE);
    _walloc_os_page_size_log2 = 64-__builtin_clzll(_walloc_os_page_size-1);
    // 16 TiB should be enough for anybody
    auto flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    #ifdef WALLOC_NOZERO
    flags |= MAP_UNINITIALIZED;
    #endif
    #ifdef WALLOC_LINUX_NO_PROT_NONE
    auto mode = PROT_READ | PROT_WRITE;
    #else
    auto mode = PROT_NONE;
    #endif
    auto ret = (char *)mmap(0, 0x100000000000, mode, flags, -1, 0);
    assert((size_t)ret != (size_t)-1);
    _walloc_heap_base = ret;
    _walloc_heap_cur.store(ret);
    _walloc_heap_top.store(ret);
    //for (size_t i = 0; i < 64; i++)
    //    assert(_walloc_heap_free[i] == 0);
    #ifdef WALLOC_CAS16
    for (size_t i = 0; i < 64; i++)
        _walloc_heap_free[i].store({0, 0});
    #endif
    return CharP{ret};
}
static CharP _walloc_heap_base_s __attribute__((init_priority(101))) = _walloc_os_init_heap();

#include <stdio.h>
static inline bool _malloc_commit_needed()
{
    #ifdef WALLOC_LINUX_NO_PROT_NONE
    return false;
    #else
    return true;
    #endif
}
static inline void _walloc_commit(char * loc, size_t over)
{
    if (mprotect(loc, over, PROT_READ | PROT_WRITE))
        assert(0);
}
static inline void _walloc_recommit(char * p2, size_t s)
{
#ifndef WALLOC_LINUX_NO_PROT_NONE
    if (s)
    {
        if (mprotect(p2, s, PROT_READ | PROT_WRITE))
            assert(0);
    }
#endif
}
static inline void _walloc_decommit(char * p, size_t n)
{
    _walloc_asan_unpoison(p, n);
    
    n -= WALLOC_OFFS;
    char * p2 = p+WALLOC_OFFS;
    size_t s = n;
    _walloc_rawmal_inner_pages(&p2, &s);
#ifdef WALLOC_LINUX_NO_MADV_FREE
    #ifndef WALLOC_NOZERO
    memset(p, 0, n + WALLOC_OFFS);
    #endif
#ifndef WALLOC_LINUX_NO_PROT_NONE
    if (s) mprotect(p2, s, PROT_NONE);
#endif
#else
    if (s)
    {
        #ifndef WALLOC_NOZERO
        memset(p, 0, p2-p);
        memset(p2+s, 0, p+n+WALLOC_OFFS-(p2+s));
        #endif
        
#ifndef WALLOC_LINUX_NO_PROT_NONE
        if (s) mprotect(p2, s, PROT_NONE);
#endif
        madvise(p2, s, MADV_DONTNEED);
    }
    else
    {
        #ifndef WALLOC_NOZERO
        memset(p, 0, n + WALLOC_OFFS);
        #endif
    }
#endif
}

#endif // else of WIN32

#endif // _WALLOC_OS_HPP
