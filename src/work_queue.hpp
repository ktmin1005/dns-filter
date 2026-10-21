#pragma once
// work_queue.hpp -- a bounded, thread-safe FIFO queue.
//
// The receiver thread try_push()es jobs; worker threads pop() them.
// Bounded on purpose: if workers fall behind (a slow upstream, or someone
// flooding the server), new jobs are dropped instead of letting memory
// grow without limit.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <utility>

template <typename T>
class WorkQueue {
public:
    explicit WorkQueue(std::size_t capacity) : capacity_(capacity) {}

    // Not copyable: a queue shared between threads must have one identity.
    WorkQueue(const WorkQueue&) = delete;
    WorkQueue& operator=(const WorkQueue&) = delete;

    // Adds an item. Returns false (and drops it) if the queue is full or closed.
    bool try_push(T item) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (closed_ || items_.size() >= capacity_) return false;
            items_.push_back(std::move(item));
        }                         // unlock before notifying, so the woken
        cv_.notify_one();         // worker doesn't immediately block on mu_
        return true;
    }

    // Blocks until an item is available. Returns std::nullopt once the queue
    // is closed and empty -- the signal for a worker to exit.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mu_);
        // The predicate guards against spurious wakeups: wait() can return
        // even when nobody notified, so always re-check the condition.
        cv_.wait(lock, [this] { return closed_ || !items_.empty(); });
        if (items_.empty()) return std::nullopt;
        T item = std::move(items_.front());
        items_.pop_front();
        return item;
    }

    // Stops accepting new items and wakes every worker. Workers finish the
    // items already queued, then pop() returns nullopt and they exit.
    void close() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            closed_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<T> items_;
    std::size_t capacity_;
    bool closed_ = false;
};
