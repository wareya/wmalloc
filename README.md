# Walloc/WMalloc

Threadsafe malloc/free/calloc/realloc implementation using raw OS primitives on Windows and Linux (other unixes may be supported but have not been tested).

Include only in a single compilation unit, and re-export wrapper functions from there if your project has more than one compilation unit. (The relevant functions are marked as `extern "C"`, so you can do this to use it from a C-only codebase, too.)

Features:

- Small implementation size
- Thread-safe
- Happy path for small objects with low contention is lock-free
- Single-heap bump-style allocation with freelists; allocations likely to be near each other in cache even if they're different sizes
- Allocations have a header to their left in memory that you are free to access and use most of; you cannot use the bottom 7 bytes of the size word, that's all
- - I use this for garbage collection metadata in a garbage collector
- Header struct can be overridden and lengthened
- Control over the safety-vs-performance tradeoffs the allocator makes, especially on linux, via defines before inclusion
- Control over allocation alignment and bump alignment via defines
- CC0 license (public domain)

## License

CC0 (public domain)

## Why C++ instead of C?

thread_local with RAII lol
