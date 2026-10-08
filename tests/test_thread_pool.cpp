#include "thread_pool.h"

#include <iostream>
#include <atomic>
#include <chrono>
#include <set>
#include <mutex>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

void assert_test(bool condition, const std::string& test_name, const std::string& details = "") {
    if (condition) {
        std::cout << "[PASS] " << test_name << std::endl;
        g_passed++;
    } else {
        std::cerr << "[FAIL] " << test_name;
        if (!details.empty()) {
            std::cerr << " (" << details << ")";
        }
        std::cerr << std::endl;
        g_failed++;
    }
}

} // namespace

int main() {
    std::cout << "Running ThreadPool Test Suite..." << std::endl;

    // Test 1: Multiple submitted tasks execute to completion
    {
        constexpr int num_tasks = 100;
        std::atomic<int> counter{0};

        {
            ThreadPool pool(4);
            for (int i = 0; i < num_tasks; ++i) {
                pool.enqueue([&counter]() {
                    counter.fetch_add(1, std::memory_order_relaxed);
                });
            }
            // pool destructor will join all worker threads after finishing tasks
        }

        assert_test(counter.load() == num_tasks,
                    "All 100 submitted tasks executed successfully",
                    "Completed: " + std::to_string(counter.load()));
    }

    // Test 2: Tasks run concurrently across multiple worker threads
    {
        constexpr int num_tasks = 20;
        std::set<std::thread::id> thread_ids;
        std::mutex ids_mutex;

        {
            ThreadPool pool(4);
            for (int i = 0; i < num_tasks; ++i) {
                pool.enqueue([&thread_ids, &ids_mutex]() {
                    // Small sleep to ensure tasks overlap across workers
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    std::lock_guard<std::mutex> lock(ids_mutex);
                    thread_ids.insert(std::this_thread::get_id());
                });
            }
        }

        assert_test(thread_ids.size() > 1,
                    "Tasks were distributed across multiple worker threads",
                    "Unique threads: " + std::to_string(thread_ids.size()));
    }

    // Test 3: Explicit stop() completes cleanly and is idempotent
    {
        std::atomic<int> completed{0};
        ThreadPool pool(2);

        for (int i = 0; i < 10; ++i) {
            pool.enqueue([&completed]() {
                completed.fetch_add(1, std::memory_order_relaxed);
            });
        }

        pool.stop();
        // Calling stop() again should be a safe no-op
        pool.stop();

        assert_test(completed.load() == 10,
                    "Explicit stop() waits for queued tasks and is idempotent",
                    "Completed: " + std::to_string(completed.load()));
    }

    std::cout << "\nTest Results: " << g_passed << " passed, " << g_failed << " failed." << std::endl;
    return g_failed == 0 ? 0 : 1;
}
