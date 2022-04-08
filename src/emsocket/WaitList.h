#pragma once

#include <chrono>
#include <condition_variable>
#include <list>
#include <mutex>

namespace emsocket {

template<typename T>
struct Waiter {
    std::vector<T> ids;
    std::condition_variable cv;

    Waiter() = delete;
    Waiter(const Waiter&) = delete;
    Waiter& operator=(const Waiter&) = delete;

    Waiter(const std::vector<T>& ids_) :
        ids(ids_) { }

    bool isWatching(const T id) const {
        for (const auto &e : ids) {
            if (e == id) {
                return true;
            }
        }
        return false;
    }

    void notify() {
        cv.notify_all();
    }
};

template<typename T>
class WaitList {
public:
    WaitList() { }
    WaitList(const WaitList&) = delete;
    WaitList& operator=(const WaitList&) = delete;

    void notify(const T id) {
        const std::lock_guard<std::mutex> lock(mutex);
        for (auto it = waiters.begin(), ie = waiters.end(); it != ie; ++it) {
            auto waiter = *it;
            if (waiter->isWatching(id)) {
                waiter->notify();
            }
        }
    }

    bool waitFor(const std::vector<T>& ids,
                 const std::function<bool(void)>& predicate,
                 int64_t timeout) {
        bool timedOut = (timeout == 0);
        bool useUntil = (timeout > 0);
        std::chrono::time_point<std::chrono::system_clock> until;
        if (useUntil) {
            until = std::chrono::system_clock::now() + std::chrono::milliseconds(timeout);
        }
        return waitInternal(ids, predicate, timedOut, useUntil, until);
    }

    bool waitInternal(const std::vector<T>& ids,
                      const std::function<bool(void)>& predicate,
                      bool timedOut,
                      bool useUntil,
                      const std::chrono::time_point<std::chrono::system_clock> &until) {
        Waiter<T> self(ids);
        std::unique_lock<std::mutex> ul(mutex);
        for (;;) {
            bool stop_waiting = predicate();
            if (stop_waiting || timedOut) {
                return stop_waiting;
            }
            auto it = waiters.insert(waiters.begin(), &self);
            if (useUntil) {
                timedOut = (self.cv.wait_until(ul, until) == std::cv_status::timeout);
            } else {
                self.cv.wait(ul);
            }
            waiters.erase(it);
        }
    }

private:
    std::mutex mutex;
    std::list<Waiter<T>*> waiters;
};


} // namespace
