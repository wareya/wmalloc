#include <thread>
#include <vector>
#include <atomic>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

// mimalloc
//#include <mimalloc.h>
//#define malloc mi_malloc
//#define free mi_free

// glibc
//__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
//#define malloc _malloc

// boehm
#define GC_THREADS
#include <gc.h>
#define malloc(X) GC_malloc((X))
#define free(X) GC_free((X))

std::atomic_int tc = 0;

using namespace std;

int * ptrs[512][8];
unsigned long looper(void *)
{
    #ifdef GC_INIT
    GC_INIT();
    #endif
    
    int unique = tc.fetch_add(1);
    for (int i = 0; i < 100000; ++i)
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

#include <pthread.h>

int main()
{
    #ifdef GC_INIT
    GC_INIT();
    #endif
    
    int threadcount = 8;
    vector<HANDLE> threads;
    
    for (int i = 0; i < threadcount; ++i)
        threads.emplace_back(CreateThread(nullptr, 0, &looper, 0, 0, 0));

    for (HANDLE thread : threads)
    {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }

    puts("Done!");
    return 0;
}