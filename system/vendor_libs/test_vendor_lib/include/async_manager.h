#ifndef TEST_VENDOR_LIB_ASYNC_MANAGER_H_
#define TEST_VENDOR_LIB_ASYNC_MANAGER_H_

#include <time.h>
#include <cstdint>
#include <map>
#include <set>
#include "errno.h"
#include "stdio.h"

#include "osi/include/log.h"

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

namespace test_vendor_lib {

using TaskCallback = std::function<void(void)>;
using ReadCallback = std::function<void(int)>;
using CriticalCallback = std::function<void(void)>;
using AsyncTaskId = uint16_t;
constexpr uint16_t kInvalidTaskId = 0;

// Manages tasks that should be done in the future. It can watch file
// descriptors to call a given callback when it is certain that a block will not
// occur or can call a callback at a specific time (aproximately) and
// (optionally) repeat the call periodically. The class itself is thread safe in
// the sense that all its member functions can be called simultaneously from
// different concurrent thread. However, no asumption should be made about
// callback execution. The safest approach is to assume that any two callbacks
// could be executed concurrently in different threads, so code provided in
// callbacks need to actively deal with race conditions, deadlocks, etc. While
// not required, it is strongly recommended to use the Synchronize(const
// CriticalCallback&) member function to execute code inside critical sections.
// Callbacks passed to this method on the same AsyncManager object from
// different threads are granted to *NOT* run concurrently.
class AsyncManager {
 public:
  // Starts watching a file descriptor in a separate thread. The
  // on_read_fd_ready_callback() will be asynchronously called when it is
  // guaranteed that a call to read() on the FD will not block. No promise is
  // made about when in the future the callback will be called, in particular,
  // it is perfectly possible to have it called before this function returns. A
  // return of 0 means success, an error code is returned otherwise.
  int WatchFdForNonBlockingReads(int file_descriptor,
                                 const ReadCallback& on_read_fd_ready_callback);

  // If the fd was not being watched before the call will be ignored.
  void StopWatchingFileDescriptor(int file_descriptor);

  // Schedules an action to occur in the future. Even if the delay given is not
  // positive the callback will be called asynchronously.
  AsyncTaskId ExecAsync(std::chrono::milliseconds delay,
                        const TaskCallback& callback);

  // Schedules an action to occur periodically in the future. If the delay given
  // is not positive the callback will be asynchronously called once for each
  // time in the past that it should have been called and then scheduled for
  // future times.
  AsyncTaskId ExecAsyncPeriodically(std::chrono::milliseconds delay,
                                    std::chrono::milliseconds period,
                                    const TaskCallback& callback);

  // Cancels the/every future ocurrence of the action specified by this id. It
  // is guaranteed that the asociated callback will not be called after this
  // method returns (it could be called during the execution of the method).
  // The calling thread may block until the scheduling thread acknowledges the
  // cancelation.
  bool CancelAsyncTask(AsyncTaskId async_task_id);

  // Execs the given code in a synchronized manner. It is guaranteed that code
  // given on (possibly)concurrent calls to this member function on the same
  // AsyncManager object will never be executed simultaneously. It is the
  // class's user's resposability to ensure that no calls to Synchronize are
  // made from inside a CriticalCallback, since that would cause a lock to be
  // acquired twice with unpredictable results. It is strongly recommended to
  // have very simple CriticalCallbacks, preferably using lambda expressions.
  void Synchronize(const CriticalCallback&);

  AsyncManager();

  ~AsyncManager();

 private:
  // Implementation of the FD watching part of AsyncManager, extracted to its
  // own class for clarity purposes.
  class AsyncFdWatcher;

  // Implementation of the asynchronous tasks part of AsyncManager, extracted to
  // its own class for clarity purposes.
  class AsyncTaskManager;

  AsyncManager(const AsyncManager&) = delete;
  AsyncManager& operator=(const AsyncManager&) = delete;

  // Kept as pointers because we may want to support reseting either without
  // destroying the other one
  std::unique_ptr<AsyncFdWatcher> fdWatcher_p_;
  std::unique_ptr<AsyncTaskManager> taskManager_p_;

  std::mutex synchronization_mutex_;
};
}
#endif  // TEST_VENDOR_LIB_ASYNC_MANAGER_H_
