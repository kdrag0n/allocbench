#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <malloc.h>

#include <unordered_map>
#include <vector>
#include <iostream>
#include <fstream>

static constexpr int RUNS = 25;
static constexpr bool SKIP_NULL_CHECK = true; // for SQL trace
static constexpr bool DEBUG = true;

enum mem_op {
    MALLOC,
    CALLOC,
    MEMALIGN,
    REALLOC,
    FREE,
    THREAD_DONE,
};

struct mem_event {
    int thread;
    enum mem_op op;
    int ptr_id;

    union {
        struct {
            size_t size;
        } malloc_args;
        struct {
            size_t nmemb;
            size_t size;
        } calloc_args;
        struct {
            size_t alignment;
            size_t size;
        } memalign_args;
        struct {
            int old_ptr_id;
            size_t size;
        } realloc_args;
        // free and thread_done have no extra args
    };
};

static uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_nsec + (ts.tv_sec * 1000000000);
}

static inline void print_event(struct mem_event event) {
    switch (event.op) {
    case MALLOC:
        printf("%d: malloc %d %zu\n", event.thread, event.ptr_id, event.malloc_args.size);
        break;
    case CALLOC:
        printf("%d: calloc %d %zu %zu\n", event.thread, event.ptr_id, event.calloc_args.nmemb, event.calloc_args.size);
        break;
    case MEMALIGN:
        printf("%d: memalign %d %zu %zu\n", event.thread, event.ptr_id, event.memalign_args.alignment, event.memalign_args.size);
        break;
    case REALLOC:
        printf("%d: realloc %d %d %zu\n", event.thread, event.ptr_id, event.realloc_args.old_ptr_id, event.realloc_args.size);
        break;
    case FREE:
        printf("%d: free %d\n", event.thread, event.ptr_id);
        break;
    case THREAD_DONE:
        printf("%d: thread_done %d\n", event.thread, event.ptr_id);
        break;
    }
}

static int page_size = getpagesize();

static inline void touch_alloc(void* ptr, size_t size) {
    uint8_t* buf = static_cast<uint8_t*>(ptr);
    for (size_t i = 0; i < size; i += page_size) {
        buf[i] = 1;
    }
}

static int run_event(std::vector<void*>& ptrs, struct mem_event event) {
    void* ptr;

    if (DEBUG) {
        print_event(event);
    }

    if (!SKIP_NULL_CHECK && event.op != REALLOC && event.op != FREE && ptrs[event.ptr_id] != nullptr) {
        fprintf(stderr, "Expected null pointer for ID 0x%llx, got %p\n", event.ptr_id, ptrs[event.ptr_id]);
        return 2;
    }

    switch (event.op) {
    case MALLOC:
        ptr = malloc(event.malloc_args.size);
        if (!ptr) {
            return 1;
        }

        touch_alloc(ptr, event.malloc_args.size);
        break;
    case CALLOC:
        ptr = calloc(event.calloc_args.nmemb, event.calloc_args.size);
        if (!ptr) {
            return 1;
        }

        touch_alloc(ptr, event.calloc_args.nmemb * event.calloc_args.size);
        break;
    case MEMALIGN:
        ptr = memalign(event.memalign_args.alignment, event.memalign_args.size);
        if (!ptr) {
            return 1;
        }

        touch_alloc(ptr, event.memalign_args.size);
        break;
    case REALLOC: {
        void* old_ptr = ptrs[event.realloc_args.old_ptr_id];
        ptr = realloc(old_ptr, event.realloc_args.size);
        if (!ptr) {
            return 1;
        }

        touch_alloc(ptr, event.realloc_args.size);
        ptrs[event.realloc_args.old_ptr_id] = nullptr;
        if (!SKIP_NULL_CHECK && ptrs[event.ptr_id] != nullptr) {
            fprintf(stderr, "Expected null pointer for ID 0x%llx, got %p\n", event.ptr_id, ptrs[event.ptr_id]);
            return 2;
        }
        break;
    }
    case FREE:
        ptr = ptrs[event.ptr_id];
        free(ptr);
        ptrs[event.ptr_id] = nullptr;
        return 0;
    case THREAD_DONE:
        // we don't have threads
        return 0;
    }

    ptrs[event.ptr_id] = ptr;
    return 0;
}

static inline uint64_t parse_hex(char* hex) {
    if (!strncmp(hex, "0x", 2)) {
        hex += 2;
    }

    return strtoull(hex, NULL, 16);
}

static int get_ptr_idx(std::unordered_map<uint64_t, int>& ptr_map, std::vector<void*>& ptrs, char* hex_id) {
    uint64_t ptr_src_id = parse_hex(hex_id);
    if (ptr_map.find(ptr_src_id) == ptr_map.end()) {
        ptrs.push_back(nullptr);
        ptr_map[ptr_src_id] = ptrs.size() - 1;
    }

    return ptr_map[ptr_src_id];
}

static int parse_events(std::vector<struct mem_event>& events, std::vector<void*>& ptrs, char* path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Failed to open trace file" << std::endl;
        return 1;
    }

    std::unordered_map<uint64_t, int> ptr_map;
    std::string line;
    while (std::getline(file, line)) {
        struct mem_event event;
        char hex_id[strlen("0xAAAADEADBEEFAAAA") + 1];
        char hex_id2[strlen("0xAAAADEADBEEFAAAA") + 1];

        if (DEBUG) {
            std::cout << "Parsing line: " << line << std::endl;
        }

        if (line.find("malloc") != std::string::npos && sscanf(line.c_str(), "%d: malloc %s %zu", &event.thread, hex_id, &event.malloc_args.size) == 3) {
            event.op = MALLOC;
        } else if (line.find("calloc") != std::string::npos && sscanf(line.c_str(), "%d: calloc %s %zu %zu", &event.thread, hex_id, &event.calloc_args.nmemb, &event.calloc_args.size) == 4) {
            event.op = CALLOC;
        } else if (line.find("memalign") != std::string::npos && sscanf(line.c_str(), "%d: memalign %s %zu %zu", &event.thread, hex_id, &event.memalign_args.alignment, &event.memalign_args.size) == 4) {
            event.op = MEMALIGN;
        } else if (line.find("realloc") != std::string::npos && sscanf(line.c_str(), "%d: realloc %s %s %zu", &event.thread, hex_id, hex_id2, &event.realloc_args.size) == 4) {
            event.op = REALLOC;
            event.realloc_args.old_ptr_id = get_ptr_idx(ptr_map, ptrs, hex_id2);
        } else if (line.find("free") != std::string::npos && sscanf(line.c_str(), "%d: free %s", &event.thread, hex_id) == 2) {
            event.op = FREE;
        } else if (line.find("thread_done") != std::string::npos && sscanf(line.c_str(), "%d: thread_done %s", &event.thread, hex_id) == 2) {
            event.op = THREAD_DONE;
        } else {
            std::cerr << "Unrecognized event: " << line << std::endl;
            file.close();
            return 1;
        }

        event.ptr_id = get_ptr_idx(ptr_map, ptrs, hex_id);
        events.push_back(event);
    }

    file.close();
    return 0;
}

void clear_ptrs(std::vector<void*>& ptrs) {
    for (auto i = 0; i < ptrs.size(); i++) {
        if (ptrs[i] != nullptr) {
            free(ptrs[i]);
        }

        ptrs[i] = nullptr;
    }
}

void print_mem_usage() {
    pid_t pid = getpid();
    std::ifstream file("/proc/" + std::to_string(pid) + "/status");
    if (!file.is_open()) {
        std::cerr << "Failed to open process status file" << std::endl;
        return;
    }

    size_t rss;
    size_t vsz;
    std::string line;
    while (std::getline(file, line)) {
        sscanf(line.c_str(), "VmSize: %zu kB", &vsz);
        sscanf(line.c_str(), "VmRSS: %zu kB", &rss);
    }

    std::cout << "Final memory usage (RSS): " << rss << " KiB" << std::endl;
    std::cout << "Final virtual memory (VSZ): " << vsz << " KiB" << std::endl;
}

int main(int argc, char** argv) {
    std::vector<struct mem_event> events;
    std::vector<void*> ptrs;

    std::cout << "Loading events..." << std::endl;
    int ret = parse_events(events, ptrs, argv[1]);
    if (ret) {
        return 1;
    }
    std::cout << "Loaded " << events.size() << " events." << std::endl << std::endl;

    std::cout << "Running events..." << std::endl;
    uint64_t total_ns = 0;
    for (auto run = 0; run < RUNS; run++) {
        clear_ptrs(ptrs);

        uint64_t before = get_time_ns();
        for (auto i = 0; i < events.size(); i++) {
            ret = run_event(ptrs, events[i]);
            if (ret) {
                printf("Error running event: ");
                print_event(events[i]);
                return 1;
            }
        }

        uint64_t elapsed_ns = get_time_ns() - before;
        total_ns += elapsed_ns;
        std::cout << "  Run " << run << ": " << elapsed_ns / 1e6 << " ms" << std::endl;
    }

    double avg_ms = static_cast<double>(total_ns) / RUNS / 1e6;
    std::cout << "Finished running " << events.size() << " events " << RUNS << " times, avg " << avg_ms << " ms per iteration." << std::endl;
    print_mem_usage();
}
