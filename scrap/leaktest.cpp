#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <thread>

void looper()
{
	
}

int main()
{
    int threadcount = 32;
    std::vector<std::thread> threads;
    
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