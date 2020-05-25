#ifndef TARAXA_NODE_UTIL_SIMPLE_EVENT_HPP_
#define TARAXA_NODE_UTIL_SIMPLE_EVENT_HPP_

#include <functional>
#include <shared_mutex>
#include <unordered_map>

namespace taraxa::util::simple_event {
using namespace std;

template <typename... Ts>
class SimpleEvent {
  using handler_t = function<void(Ts const &... ts)>;

  mutable uint64_t next_id;
  mutable unordered_map<uint64_t, handler_t> handlers;
  mutable shared_mutex mu;

 public:
  void pub(Ts const &... ts) const {
    shared_lock l(mu);
    for (auto const &[_, handler] : handlers) {
      handler(ts...);
    }
  }

  uint64_t sub(handler_t &&handler) const {
    unique_lock l(mu);
    auto id = next_id++;
    handlers[id] = move(handler);
    return id;
  }

  bool unsub(uint64_t id) const {
    unique_lock l(mu);
    return handlers.erase(id);
  }
};

}  // namespace taraxa::util::simple_event

namespace taraxa::util {
using simple_event::SimpleEvent;
}

#endif  // TARAXA_NODE_UTIL_SIMPLE_EVENT_HPP_
