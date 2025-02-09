#include <thread>
#include <vector>
#include <atomic>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

// glibc
//__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
//#define malloc _malloc
//
#define GC_NO_PREFIX
//#define GC_SYSTEM_MALLOC
//#define GC_SYSTEM_MALLOC_PREFIX(X) mi_ ## X
//#define WALLOC_NOZERO
#include "gc.hpp"
void * X_malloc(size_t n)
{
    auto r = gc_malloc(n);
    gc_set_trace_none(r);
    return r;
}

//#define malloc(X) gc_malloc((X))
#define malloc(X) X_malloc((X))
#define free(X) gc_free((X))
#define realloc(X, Y) gc_realloc((X), (Y))
#define calloc(X, Y) gc_malloc((X)*(Y))

using namespace std;
std::atomic_int tc = 0;

int * ptrs[512][8];
void * looper()
{
    int unique = tc.fetch_add(1);
    for (int i = 0; i < 1000000; ++i)
    {
        for (int j = 0; j < 8; j++)
        {
            ptrs[unique][j] = (int *)(malloc(sizeof(int)));
            *ptrs[unique][j] = j+unique*1523;
        }
        for (int j = 8; j > 0; j--)
        {
            if (*ptrs[unique][j-1] != j-1+unique*1523)
                assert(((void)"memory corruption! (FILO)", 0));
            free(ptrs[unique][j-1]);
        }
        
        for (int j = 0; j < 8; j++)
        {
            ptrs[unique][j] = (int *)(malloc(sizeof(int)));
            *ptrs[unique][j] = j+unique*1523;
        }
        for (int j = 0; j < 8; j++)
        {
            if (*ptrs[unique][j] != j+unique*1523)
                assert(((void)"memory corruption! (FIFO)", 0));
            free(ptrs[unique][j]);
        }
    }
    return 0;
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
