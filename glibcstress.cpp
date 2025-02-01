// custom malloc
/*
#define WALLOC_CUSTOMALIGN 32
#define WALLOC_CACHEHINT 64
#include "wmalloc.hpp"
#define malloc _walloc_raw_malloc
#define calloc _walloc_raw_calloc
#define realloc _walloc_raw_realloc
#define free _walloc_raw_free
*/

//#define GC_NO_PREFIX

#include <thread>
#include <vector>
#include <atomic>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
using namespace std;

// mimalloc
//#include <mimalloc.h>
//#define malloc mi_malloc
//#define free mi_free

// glibc
__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
#define malloc _malloc

std::atomic_int tc = 0;

int * ptrs[512][8];
void looper()
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
    //puts("!!!!!!!!!!!!!!! thread finished !!!!!!!!!!!!");
    //printf("!!!! thread %zd finished !!!!\n", _thread_info->alt_id);
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
        thread.join();
    }
    
    puts("Done!");
    return 0;
}