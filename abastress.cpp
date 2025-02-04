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
#define GC_SYSTEM_MALLOC
//#define GC_SYSTEM_MALLOC_PREFIX(X) mi_ ## X
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

#define malloc(X) gc_malloc((X))
//#define malloc(X) X_malloc((X))
#define free(X) gc_free((X))
#define realloc(X, Y) gc_realloc((X), (Y))
#define calloc(X, Y) gc_malloc((X)*(Y))

// glibc
//__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
//#define malloc _malloc

std::atomic_int tc = 0;

typedef size_t alloc_type;

alloc_type * ptrs[512][8];

void dumpall(size_t i)
{
    printf("thread %zd:\n", i);
    for (size_t j = 0; j < 8; j++)
        printf("alloc %zd: %p\n", j, (void *)ptrs[i][j]);
    puts("----");
}

const size_t factor = 1024;

void looper()
{
    gc_add_current_thread();
    
    size_t unique = tc.fetch_add(1);
    for (int i = 0; i < 100000; ++i)
    {
        size_t s = 1ULL << (i%20);
        
        for (int j = 0; j < 8; j++)
        {
            ptrs[unique][j] = (alloc_type *)(malloc(sizeof(alloc_type)*s));
            *ptrs[unique][j] = j+unique*factor;
        }
        for (int j = 8; j > 0; j--)
        {
            if (*ptrs[unique][j-1] != j-1+unique*factor)
            {
                size_t other_unique = (*ptrs[unique][j-1])/factor;
                size_t other_j = (*ptrs[unique][j-1]) % factor;
                alloc_type * evidence = std::atomic_ref(ptrs[other_unique][other_j]).load();
                printf("%p\n", (void *)evidence);
                printf("%p\n", (void *)ptrs[unique][j-1]);
                printf("(%zd %d) %016zu %016zu\n", unique, j, *ptrs[unique][j-1], j-1+unique*factor);
                printf("%zd\n", other_j);
                dumpall(unique);
                dumpall(other_unique);
                assert(((void)"memory corruption! (FILO)", 0));
            }
            free(ptrs[unique][j-1]);
        }
        
        for (int j = 0; j < 8; j++)
        {
            ptrs[unique][j] = (alloc_type *)(malloc(sizeof(alloc_type)*s));
            *ptrs[unique][j] = j+unique*factor;
        }
        for (int j = 0; j < 8; j++)
        {
            if (*ptrs[unique][j] != j+unique*factor)
            {
                size_t other_unique = (*ptrs[unique][j])/factor;
                size_t other_j = (*ptrs[unique][j]) % factor;
                alloc_type * evidence = std::atomic_ref(ptrs[other_unique][other_j]).load();
                printf("%p\n", (void *)evidence);
                printf("%p\n", (void *)ptrs[unique][j]);
                printf("(%zd %d) %016zu %016zu\n", unique, j, *ptrs[unique][j], j+unique*factor);
                printf("%zd\n", other_j);
                dumpall(unique);
                dumpall(other_unique);
                assert(((void)"memory corruption! (FIFO)", 0));
            }
            free(ptrs[unique][j]);
        }
    }
    //puts("!!!!!!!!!!!!!!! thread finished !!!!!!!!!!!!");
    printf("!!!! thread %zd (id %zd) finished !!!!\n", _thread_info->alt_id, unique);
    fflush(stdout);
}

int main()
{
    int threadcount = 32;
    vector<thread> threads;
    
    for (int i = 0; i < threadcount; ++i)
        threads.emplace_back(looper);
    
    for (auto & thread : threads)
    {
        _gc_safepoint_long_start();
        thread.join();
        _gc_safepoint_long_end();
    }
    
    puts("Done!");
    return 0;
}