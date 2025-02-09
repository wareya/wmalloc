#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
using namespace std::chrono_literals;
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <malloc.h>
using namespace std;

// custom malloc
//#define WALLOC_SYS_MALLOC
//#define WALLOC_GLOBAL_FREELIST
#define WALLOC_PULL_OVERRIDE (256*128)
#define WALLOC_FLUSH_OVERRIDE (4096*64)
#define WALLOC_FLUSH_KEEP_OVERRIDE 0
#define WALLOC_MAXIMUM_FAST
//#define WALLOC_CACHEHINT 64
#include "wmalloc.hpp"
#define malloc _walloc_raw_malloc
#define calloc _walloc_raw_calloc
#define realloc _walloc_raw_realloc
#define free _walloc_raw_free

// glibc
//__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
//#define malloc _malloc

struct FairMutex {
private:
    std::atomic<size_t> next_ticket{0};   // The next ticket to be issued
    std::atomic<size_t> serving_ticket{0}; // The ticket number being served

public:
    void lock() {
        size_t my_ticket = next_ticket.fetch_add(1, std::memory_order_relaxed); // Get a ticket
        while (serving_ticket.load(std::memory_order_acquire) != my_ticket) {
            std::this_thread::yield(); // Wait until our ticket is served
        }
    }

    void unlock() {
        serving_ticket.fetch_add(1, std::memory_order_release); // Serve next ticket
    }
};

FairMutex global_tofree_list_mtx;
std::vector<void *> global_tofree_list;

std::atomic_int mustexit;
void freeloop()
{
    size_t max_list_bytes = 0;
    size_t max_list_size = 0;
    while (1)
    {
        size_t s = 0;
        size_t list_bytes = 0;
        
        global_tofree_list_mtx.lock();
        
        s = global_tofree_list.size();
        for (auto & p : global_tofree_list)
        {
            list_bytes += (WAllocHeaderPtr(((char*)p)-WALLOC_OFFS)->size)<<8>>8;
            free(p);
        }
        global_tofree_list.clear();
        
        global_tofree_list_mtx.unlock();

        if (s > max_list_size)
        {
            printf("new size %zd\n", s);
            max_list_size = s;
            fflush(stdout);
        }
        if (list_bytes > max_list_bytes)
        {
            if (s)
                printf("%zd\n", list_bytes);
            max_list_bytes = list_bytes;
            fflush(stdout);
        }

        if (mustexit)
            return;
    }
}

std::atomic_int tc = 0;
int * ptrs[512][8];
void looper()
{
    std::vector<void *> tofree_list;
    auto do_free = [&](void * p)
    {
        tofree_list.push_back(p);
        if (tofree_list.size() > 100)
        {
            global_tofree_list_mtx.lock();
            for (auto & p : tofree_list)
                global_tofree_list.push_back(p);
            global_tofree_list_mtx.unlock();
            tofree_list.clear();
        }
    };
    int unique = tc.fetch_add(1);
    for (int i = 0; i < 1000000; ++i)
    {
        size_t s = 1ULL << (i%20);
        for (int j = 0; j < 8; j++)
        {
            ptrs[unique][j] = (int *)(malloc(s*sizeof(int)));
            *ptrs[unique][j] = j+unique*10000;
        }
        for (int j = 8; j > 0; j--)
        {
            if (*ptrs[unique][j-1] != j-1+unique*10000)
                assert(((void)"memory corruption! (FILO)", 0));
            free(ptrs[unique][j-1]);
        }
        
        for (int j = 0; j < 8; j++)
        {
            ptrs[unique][j] = (int *)(malloc(s*sizeof(int)));
            *ptrs[unique][j] = j+unique*10000;
        }
        for (int j = 0; j < 8; j++)
        {
            if (*ptrs[unique][j] != j+unique*10000)
                assert(((void)"memory corruption! (FIFO)", 0));
            free(ptrs[unique][j]);
        }
    }
    global_tofree_list_mtx.lock();
    for (auto & p : tofree_list)
        global_tofree_list.push_back(p);
    global_tofree_list_mtx.unlock();
    tofree_list.clear();
    //puts("!!!!!!!!!!!!!!! thread finished !!!!!!!!!!!!");
    //printf("!!!! thread %zd finished !!!!\n", _thread_info->alt_id);
    fflush(stdout);
}

int main()
{
    int threadcount = 1;
    vector<thread> threads;
    
    for (int i = 0; i < threadcount; ++i)
        threads.emplace_back(looper);
    
    std::thread freeloop_thread(freeloop);
    
    for (auto & thread : threads)
    {
        thread.join();
    }
    
    mustexit.store(1);
    freeloop_thread.join();
    
    puts("Done!");
    
    return 0;
}