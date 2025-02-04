#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
using namespace std::chrono_literals;
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
using namespace std;

// mimalloc
#include <mimalloc.h>
#define malloc mi_malloc
#define free mi_free

// glibc
//__attribute__((optnone)) void * _malloc(size_t n) { return malloc(n); }
//#define malloc _malloc

std::mutex global_tofree_list_mtx;
std::vector<void *> global_tofree_list;

std::atomic_int mustexit;
void freeloop()
{
    //int i = 0;
    while (1)
    {
        //printf("%d\n", i++);
        global_tofree_list_mtx.lock();
        /*
        if (global_tofree_list.size())
            printf("%zd\n", global_tofree_list.size());
        */
        for (auto & p : global_tofree_list)
            free(p);
        global_tofree_list.clear();
        
        if (mustexit)
        {
            global_tofree_list_mtx.unlock();
            return;
        }
        
        /*
        while (global_tofree_list.size())
        {
            free(global_tofree_list.back());
            global_tofree_list.pop_back();
        }
        */
        global_tofree_list_mtx.unlock();
        //_walloc_flush_freelists();
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
    for (int i = 0; i < 100000; ++i)
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
            do_free(ptrs[unique][j-1]);
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
            do_free(ptrs[unique][j]);
        }
    }
    global_tofree_list_mtx.lock();
    for (auto & p : tofree_list)
        global_tofree_list.push_back(p);
    global_tofree_list_mtx.unlock();
    tofree_list.clear();
    puts("thread done!");
    std::this_thread::sleep_for(10000ms);
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