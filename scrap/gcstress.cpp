// custom malloc
//#define WALLOC_CACHEHINT 64
/*
#include "wmalloc.hpp"
#define malloc _walloc_raw_malloc
#define calloc _walloc_raw_calloc
#define realloc _walloc_raw_realloc
#define free _walloc_raw_free
*/

#include <thread>
#include <vector>
#include <atomic>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
using namespace std;

// mimalloc
//#include <mimalloc.h>

//#define GC_NO_PREFIX
//#define GC_SYSTEM_MALLOC
//#define GC_SYSTEM_MALLOC_PREFIX(X) mi_ ## X
#define WALLOC_NOZERO
#include "gc.hpp"
void * X_malloc(size_t n)
{
    auto r = gc_malloc(n);
    gc_set_trace_none(r);
    return r;
}
#undef malloc
#undef calloc
#undef free

//#define malloc(X) gc_malloc((X))
#define malloc(X) X_malloc((X))
#define free(X) gc_free((X))
#define realloc(X, Y) gc_realloc((X), (Y))
#define calloc(X, Y) gc_malloc((X)*(Y))

// glibc
//__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
//#define malloc _malloc

std::atomic_int tc = 0;

typedef size_t alloc_type;

//alloc_type * ptrs[512][8];
alloc_type *** ptrs;

void dumpall(size_t i)
{
    printf("thread %zd:\n", i);
    for (size_t j = 0; j < 8; j++)
        printf("alloc %zd: %p\n", j, (void *)ptrs[i][j]);
    puts("----");
}

const size_t factor = 1024;

std::mutex badlock;

uint32_t threadcount = 32;

std::atomic_uint32_t threads_done = 0;

void looper()
{
    gc_add_current_thread();
    
    int shlamnt = 32;
    
    size_t unique = tc.fetch_add(1);
    
    alloc_type ** volatile local_ptrs;
    local_ptrs = ptrs[unique];
    (void)local_ptrs;
    
    for (int i = 0; i < 10000; ++i)
    {
        size_t s = 1ULL << (i%20);
        //size_t s = 1ULL << 12;
        
        for (int j = 0; j < 8; j++)
        {
            std::atomic_ref(ptrs[unique][j]).store((alloc_type *)(malloc(sizeof(alloc_type)*s)));
            fence();
            *ptrs[unique][j] = j+unique*factor + (size_t(ptrs[unique][j])<<shlamnt);
        }
        
        for (int j = 8; j > 0; j--)
        {
            auto val = *ptrs[unique][j-1];
            if (val != j-1+unique*factor + (size_t(ptrs[unique][j-1])<<shlamnt))
            {
                fence();
                size_t other_unique = (val)/factor;
                size_t other_j = (val) % factor;
                
                for (size_t a = 0; a < threadcount; a++)
                {
                    if (a == unique) continue;
                    for (size_t b = 0; b < 8; b++)
                    {
                        if (std::atomic_ref(ptrs[a][b]).load() == ptrs[unique][j-1])
                        {
                            other_unique = a;
                            other_j = b;
                            break;
                        }
                    }
                }
                
                alloc_type * evidence = std::atomic_ref(ptrs[other_unique][other_j]).load();
                printf("%p\n", (void *)evidence);
                printf("%p\n", (void *)ptrs[unique][j-1]);
                printf("(%zd %d) %016zX %016zX\n", unique, j, val, j-1+unique*factor + (size_t(ptrs[unique][j-1])<<shlamnt));
                printf("(%zd %d) %016zu %016zu\n", unique, j, val, j-1+unique*factor + (size_t(ptrs[unique][j-1])<<shlamnt));
                printf("%zd %zd\n", other_unique, other_j);
                dumpall(other_unique);
                dumpall(unique);
                
                assert(((void)"memory corruption! (FILO)", 0));
            }
            free(ptrs[unique][j-1]);
        }
        
        for (int j = 0; j < 8; j++)
        {
            std::atomic_ref(ptrs[unique][j]).store((alloc_type *)(malloc(sizeof(alloc_type)*s)));
            fence();
            *ptrs[unique][j] = j+unique*factor + (size_t(ptrs[unique][j])<<shlamnt);
        }
        
        for (int j = 0; j < 8; j++)
        {
            auto val = *ptrs[unique][j];
            if (val != j+unique*factor + (size_t(ptrs[unique][j])<<shlamnt))
            {
                fence();
                size_t other_unique = (val)/factor;
                size_t other_j = (val) % factor;
                
                for (size_t a = 0; a < threadcount; a++)
                {
                    if (a == unique) continue;
                    for (size_t b = 0; b < 8; b++)
                    {
                        if (std::atomic_ref(ptrs[a][b]).load() == ptrs[unique][j])
                        {
                            other_unique = a;
                            other_j = b;
                            break;
                        }
                    }
                }
                
                alloc_type * evidence = std::atomic_ref(ptrs[other_unique][other_j]).load();
                printf("%p\n", (void *)evidence);
                printf("%p\n", (void *)ptrs[unique][j]);
                printf("(%zd %d) %016zX %016zX\n", unique, j, val, j+unique*factor + (size_t(ptrs[unique][j])<<shlamnt));
                printf("(%zd %d) %016zu %016zu\n", unique, j, val, j+unique*factor + (size_t(ptrs[unique][j])<<shlamnt));
                printf("%zd %zd\n", other_unique, other_j);
                dumpall(other_unique);
                dumpall(unique);
                
                assert(((void)"memory corruption! (FIFO)", 0));
            }
            free(ptrs[unique][j]);
        }
    }
    //puts("!!!!!!!!!!!!!!! thread finished !!!!!!!!!!!!");
    printf("!!!! thread %zd (id %zd) finished !!!!\n", _thread_info->alt_id, unique);
    fflush(stdout);
    threads_done.fetch_add(1);
}

int main()
{
    gc_add_current_thread();
    
    ptrs = (alloc_type ***)gc_malloc(sizeof(alloc_type **) * threadcount);
    for (size_t i = 0; i < threadcount; i++)
    {
        ptrs[i] = (alloc_type **)gc_malloc(sizeof(alloc_type *) * 8);
    }
    vector<thread> threads;
    
    for (size_t i = 0; i < threadcount; ++i)
        threads.emplace_back(looper);
    
    while (threads_done.load() < threadcount)
    {
        gc_safepoint(0);
        std::this_thread::yield();
    }
    
    for (auto & thread : threads)
    {
        _gc_safepoint_long_start();
        thread.join();
        _gc_safepoint_long_end();
    }
    
    puts("Done!");
    return 0;
}