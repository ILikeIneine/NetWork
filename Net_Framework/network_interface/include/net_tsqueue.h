#pragma once

#include "net_common.h"

namespace hnk::net
{

template <typename T>
class tsqueue
{
protected:
  std::mutex mtx_queue_;
  std::condition_variable cv_blocking_;
  std::deque<T> queue_;
  std::mutex mtx_blocking_;

public:
  tsqueue() = default;
  tsqueue(const tsqueue&) = delete;
  virtual ~tsqueue() { clear(); }

  const T& front()
  {
    return queue_.front();
  }

  const T& back()
  {
    return queue_.back();
  }

  T pop_back()
  {
    std::scoped_lock lk(mtx_queue_);
    auto item = std::move(queue_.back());
    queue_.pop_back();
    return item;
  }

  T pop_front()
  {
    std::scoped_lock lk(mtx_queue_);
    auto item = std::move(queue_.front());
    queue_.pop_front();
    return item;
  }

  void push_back(const T& val)
  {
    std::scoped_lock lk(mtx_queue_);
    queue_.emplace_back(std::move(val));

    std::unique_lock ul(mtx_blocking_);
    cv_blocking_.notify_one();
  }

  void push_front(const T& val)
  {
    std::scoped_lock lk(mtx_queue_);
    queue_.emplace_front(std::move(val));

    std::unique_lock ul(mtx_blocking_);
    cv_blocking_.notify_one();
  }

  size_t count()
  {
    std::scoped_lock lk(mtx_queue_);
    return queue_.size();
  }

  bool empty()
  {
    std::scoped_lock lk(mtx_queue_);
    return queue_.empty();
  }

  void clear()
  {
    std::scoped_lock lk(mtx_queue_);
    queue_.clear();
  }

  void wait()
  {
      std::unique_lock lk(mtx_blocking_);
      cv_blocking_.wait(lk, [this] { return !empty(); });
  }

};

}
