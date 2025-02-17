#pragma once

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "logger/logger.hpp"
#include "priority_queue.hpp"

namespace taraxa::network::tarcap {

class PacketsHandler;

/**
 * @brief Taraxa ThreadPool that is supposed to process incoming packets in concurrent way
 **/
class TarcapThreadPool {
 public:
  /**
   * @param workers_num  Number of workers
   **/
  TarcapThreadPool(size_t workers_num = 10, const addr_t& node_addr = {});
  ~TarcapThreadPool();

  TarcapThreadPool(const TarcapThreadPool&) = delete;
  TarcapThreadPool& operator=(const TarcapThreadPool&) = delete;
  TarcapThreadPool(TarcapThreadPool&&) = delete;
  TarcapThreadPool& operator=(TarcapThreadPool&&) = delete;

  /**
   * @brief Push the given element value to the end of the queue. Used for r-values
   *
   * @return packet unique ID. In case push was not successful, empty optional is returned
   **/
  std::optional<uint64_t> push(PacketData&& packet_data);

  /**
   * @brief Start all processing threads
   */
  void startProcessing();

  /**
   * @brief Stop all processing threads
   */
  void stopProcessing();

  /**
   * @brief Threadpool sycnchronized processing function, which internally calls packet-specific handlers
   **/
  void processPacket(size_t worker_id);

  /**
   * @brief Sets packet handler
   *
   * @param packets_handlers
   */
  void setPacketsHandlers(std::shared_ptr<PacketsHandler> packets_handlers);

  /**
   * @brief Returns actual size of all priority queues (thread-safe)
   *
   * @return std::tuple<size_t, size_t, size_t> - > std::tuple<HighPriorityQueue.size(), MidPriorityQueue.size(),
   * LowPriorityQueue.size()>
   */
  std::tuple<size_t, size_t, size_t> getQueueSize() const;

 private:
  // Declare logger instances
  LOG_OBJECTS_DEFINE

  // Number of workers(threads)
  const size_t workers_num_;

  // Common packets handler
  std::shared_ptr<PacketsHandler> packets_handlers_;

  // If true, stop processing packets and join all workers threads
  bool stopProcessing_{false};

  // How many packets were pushed into the queue, it also serves for creating packet unique id
  uint64_t packets_count_{0};

  // Queue of unprocessed packets
  PriorityQueue queue_;

  // Queue mutex
  std::mutex queue_mutex_;

  // Queue condition variable
  std::condition_variable cond_var_;

  // Vector of worker threads - should be initialized as the last member
  std::vector<std::thread> workers_;
};

}  // namespace taraxa::network::tarcap
