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

using namespace std;
std::atomic_int tc = 0;

int * ptrs[512][8];
unsigned long looper(void *)
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

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX

#include <windows.h>

int main()
{
    #ifdef GC_INIT
    GC_INIT();
    #endif
    
    int threadcount = 32;
    std::vector<HANDLE> threads;
    
    for (int i = 0; i < threadcount; ++i)
    {
        HANDLE thread = CreateThread(nullptr, 0, looper, nullptr, 0, nullptr);
        assert(thread);
        threads.emplace_back(thread);
    }
    
    WaitForMultipleObjects(threads.size(), threads.data(), TRUE, INFINITE);
    
    for (auto &thread : threads)
        CloseHandle(thread);
    
    puts("Done!");
    return 0;
}
