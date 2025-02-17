#include <gtest/gtest.h>
#include <libdevcrypto/Common.h>
#include <libp2p/Capability.h>
#include <libp2p/Common.h>
#include <libp2p/Host.h>
#include <libp2p/Network.h>
#include <libp2p/Session.h>

#include <atomic>
#include <boost/thread.hpp>
#include <iostream>
#include <vector>

#include "common/lazy.hpp"
#include "common/static_init.hpp"
#include "config/config.hpp"
#include "logger/logger.hpp"
#include "network/network.hpp"
#include "network/tarcap/packets_handlers/dag_block_packet_handler.hpp"
#include "network/tarcap/packets_handlers/transaction_packet_handler.hpp"
#include "network/tarcap/taraxa_capability.hpp"
#include "test_util/samples.hpp"
#include "test_util/test_util.hpp"

namespace taraxa::core_tests {
using namespace dev;
using namespace dev::p2p;

const unsigned NUM_TRX = 9;
auto g_secret = Lazy([] {
  return dev::Secret("3800b2875669d9b2053c1aff9224ecfdc411423aac5b5a73d7a45ced1c3b9dcd",
                     dev::Secret::ConstructFromStringType::FromHex);
});
auto g_signed_trx_samples = Lazy([] { return samples::createSignedTrxSamples(0, NUM_TRX, g_secret); });

struct P2PTest : NodesTest {};

// TODO this needs to be removed and called from tracap->setPendingPeersToReady() directly
void setPendingPeersToReady(std::shared_ptr<taraxa::network::tarcap::TaraxaCapability> taraxa_capability) {
  const auto &peers_state = taraxa_capability->getPeersState();

  auto peerIds = peers_state->getAllPendingPeersIDs();
  for (const auto &peerId : peerIds) {
    auto peer = peers_state->getPendingPeer(peerId);
    if (peer) {
      peers_state->setPeerAsReadyToSendMessages(peerId, peer);
    }
  }
}

/*
Test creates one boot node and 10 nodes that uses that boot node
to find each other. Test confirm that after a delay each node had found
all other nodes.
*/
TEST_F(P2PTest, p2p_discovery) {
  auto secret = dev::Secret("3800b2875669d9b2053c1aff9224ecfdc411423aac5b5a73d7a45ced1c3b9dcd",
                            dev::Secret::ConstructFromStringType::FromHex);
  auto key = dev::KeyPair(secret);
  const int NUMBER_OF_NODES = 40;
  dev::p2p::NetworkConfig net_conf("127.0.0.1", 20001, false, true);
  TaraxaNetworkConfig taraxa_net_conf;
  taraxa_net_conf.is_boot_node = true;
  auto dummy_capability_constructor = [](auto /*host*/) { return Host::CapabilityList{}; };
  util::ThreadPool tp;
  auto bootHost = Host::make("TaraxaNode", dummy_capability_constructor, key, net_conf, taraxa_net_conf);
  tp.post_loop({}, [=] { bootHost->do_work(); });
  const auto &boot_node_key = bootHost->id();
  printf("Started Node id: %s\n", boot_node_key.hex().c_str());

  std::vector<std::shared_ptr<dev::p2p::Host>> nodes;
  for (int i = 0; i < NUMBER_OF_NODES; i++) {
    auto node = nodes.emplace_back(Host::make("TaraxaNode", dummy_capability_constructor, dev::KeyPair::create(),
                                              dev::p2p::NetworkConfig("127.0.0.1", 20002 + i, false, true)));
    tp.post_loop({}, [=] { node->do_work(); });
    nodes[i]->addNode(
        Node(boot_node_key, dev::p2p::NodeIPEndpoint(bi::address::from_string("127.0.0.1"), 20001, 20001)));
  }

  wait({60s, 500ms}, [&](auto &ctx) {
    for (int j = 0; j < NUMBER_OF_NODES; ++j) WAIT_EXPECT_LT(ctx, nodes[j]->getNodeCount(), NUMBER_OF_NODES / 3);
  });
}

/*
Test creates two host/network/capability and verifies that host connect
to each other and that a block packet message can be sent from one host
to the other using TaraxaCapability
*/
TEST_F(P2PTest, capability_send_block) {
  int const step = 10;
  const char *const localhost = "127.0.0.1";
  dev::p2p::NetworkConfig prefs1(localhost, 10007, false, true);
  prefs1.discovery = false;
  dev::p2p::NetworkConfig prefs2(localhost, 10003, false, true);
  prefs2.discovery = false;

  FullNodeConfig conf;
  conf.network.transaction_interval_ms = 1000;
  h256 genesis;
  std::shared_ptr<taraxa::network::tarcap::TaraxaCapability> thc1, thc2;
  auto host1 = Host::make(
      "Test",
      [&](auto host) {
        thc1 = network::tarcap::TaraxaCapability::make(host, KeyPair::create(), conf, genesis, TARAXA_NET_VERSION);
        return Host::CapabilityList{thc1};
      },
      KeyPair::create(), prefs1);
  auto host2 = Host::make(
      "Test",
      [&](auto host) {
        thc2 = network::tarcap::TaraxaCapability::make(host, KeyPair::create(), conf, genesis, TARAXA_NET_VERSION);
        return Host::CapabilityList{thc2};
      },
      KeyPair::create(), prefs2);
  util::ThreadPool tp;
  tp.post_loop({}, [=] { host1->do_work(); });
  tp.post_loop({}, [=] { host2->do_work(); });
  thc1->start();
  thc2->start();
  auto port1 = host1->listenPort();
  auto port2 = host2->listenPort();
  EXPECT_NE(port1, 0);
  EXPECT_NE(port2, 0);
  EXPECT_NE(port1, port2);

  host1->addNode(
      Node(host2->id(), NodeIPEndpoint(bi::address::from_string(localhost), port2, port2), PeerType::Required));

  // Wait for up to 12 seconds, to give the hosts time to connect to each
  // other.
  for (unsigned i = 0; i < 12000; i += step) {
    std::this_thread::sleep_for(std::chrono::milliseconds(step));
    setPendingPeersToReady(thc1);
    setPendingPeersToReady(thc2);

    if ((host1->peer_count() > 0) && (host2->peer_count() > 0)) break;
  }

  EXPECT_GT(host1->peer_count(), 0);
  EXPECT_GT(host2->peer_count(), 0);

  DagBlock blk(blk_hash_t(1111), 0, {blk_hash_t(222), blk_hash_t(333), blk_hash_t(444)},
               {g_signed_trx_samples[0]->getHash(), g_signed_trx_samples[1]->getHash()}, sig_t(7777), blk_hash_t(888),
               addr_t(999));

  SharedTransactions transactions{g_signed_trx_samples[0], g_signed_trx_samples[1]};
  thc2->getSpecificHandler<network::tarcap::TransactionPacketHandler>()->onNewTransactions(
      SharedTransactions(transactions));
  SharedTransactions transactions_to_send;
  transactions_to_send.push_back(g_signed_trx_samples[0]);
  transactions_to_send.push_back(g_signed_trx_samples[1]);
  std::vector<trx_hash_t> transactions_hashes;
  transactions_hashes.push_back(g_signed_trx_samples[0]->getHash());
  transactions_hashes.push_back(g_signed_trx_samples[1]->getHash());
  thc2->getSpecificHandler<network::tarcap::TransactionPacketHandler>()->sendTransactions(
      thc2->getPeersState()->getPeer(host1->id()), std::move(transactions_to_send));
  thc2->getSpecificHandler<network::tarcap::DagBlockPacketHandler>()->sendBlock(host1->id(), blk, {});

  std::this_thread::sleep_for(std::chrono::seconds(1));
  auto blocks = thc1->test_state_->getBlocks();
  auto rtransactions = thc1->test_state_->getTransactions();
  EXPECT_EQ(blocks.size(), 1);
  if (blocks.size()) {
    EXPECT_EQ(blk, blocks.begin()->second);
  }
  EXPECT_EQ(rtransactions.size(), 2);
  if (rtransactions.size() == 2) {
    EXPECT_EQ(*transactions[0], *rtransactions[g_signed_trx_samples[0]->getHash()]);
    EXPECT_EQ(*transactions[1], *rtransactions[g_signed_trx_samples[1]->getHash()]);
  }
}

/*
Test creates 50 host/network/capability which connect to each other
using node discovery. Block is created on one host and automatically
propagated to all other hosts. Test verifies that each node has received
the block
*/
TEST_F(P2PTest, block_propagate) {
  int const nodeCount = 10;
  const char *const localhost = "127.0.0.1";
  dev::p2p::NetworkConfig prefs1(localhost, 10007, false, true);
  std::vector<dev::p2p::NetworkConfig> vPrefs;
  for (int i = 0; i < nodeCount; i++) {
    vPrefs.push_back(dev::p2p::NetworkConfig(localhost, 10007 + i + 1, false, true));
  }
  TaraxaNetworkConfig taraxa_net_conf_1;
  taraxa_net_conf_1.is_boot_node = true;

  FullNodeConfig conf;
  conf.network.transaction_interval_ms = 1000;
  h256 genesis;
  std::shared_ptr<taraxa::network::tarcap::TaraxaCapability> thc1;
  auto host1 = Host::make(
      "Test",
      [&](auto host) {
        thc1 = network::tarcap::TaraxaCapability::make(host, KeyPair::create(), conf, genesis, TARAXA_NET_VERSION);
        thc1->start();
        return Host::CapabilityList{thc1};
      },
      KeyPair::create(), prefs1, taraxa_net_conf_1);
  util::ThreadPool tp;
  tp.post_loop({}, [=] { host1->do_work(); });
  std::vector<std::shared_ptr<Host>> vHosts;
  std::vector<std::shared_ptr<taraxa::network::tarcap::TaraxaCapability>> vCapabilities;
  for (int i = 0; i < nodeCount; i++) {
    auto host = vHosts.emplace_back(Host::make(
        "Test",
        [&](auto host) {
          auto cap = vCapabilities.emplace_back(
              network::tarcap::TaraxaCapability::make(host, KeyPair::create(), conf, genesis, TARAXA_NET_VERSION));
          cap->start();
          return Host::CapabilityList{cap};
        },
        KeyPair::create(), vPrefs[i]));
    tp.post_loop({}, [=] { host->do_work(); });
  }
  printf("Starting %d hosts\n", nodeCount);
  auto port1 = host1->listenPort();
  EXPECT_NE(port1, 0);
  for (int i = 0; i < nodeCount; i++) {
    EXPECT_NE(vHosts[i]->listenPort(), 0);
    EXPECT_NE(port1, vHosts[i]->listenPort());
    for (int j = 0; j < i; j++) EXPECT_NE(vHosts[j]->listenPort(), vHosts[i]->listenPort());
  }

  for (int i = 0; i < nodeCount; i++) {
    if (i < 10)
      vHosts[i]->addNode(Node(host1->id(), NodeIPEndpoint(bi::address::from_string(localhost), port1, port1)));
    else
      vHosts[i]->addNode(
          Node(vHosts[i % 10]->id(), NodeIPEndpoint(bi::address::from_string(localhost), vHosts[i % 10]->listenPort(),
                                                    vHosts[i % 10]->listenPort())));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  printf("Addnode %d hosts\n", nodeCount);

  // Wait for to give the hosts time to connect to each
  // other.
  bool connected = false;
  for (unsigned i = 0; i < 500; i++) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    connected = true;
    setPendingPeersToReady(thc1);
    for (int j = 0; j < nodeCount; j++) {
      setPendingPeersToReady(vCapabilities[j]);
      if (vHosts[j]->peer_count() < 1) connected = false;
    }

    if ((host1->peer_count() > 0) && connected) break;
  }
  EXPECT_TRUE(connected);
  EXPECT_GT(host1->peer_count(), 0);

  DagBlock blk(blk_hash_t(1111), 0, {blk_hash_t(222), blk_hash_t(333), blk_hash_t(444)},
               {g_signed_trx_samples[0]->getHash(), g_signed_trx_samples[1]->getHash()}, sig_t(7777), kNullBlockHash,
               addr_t(999));

  SharedTransactions transactions{g_signed_trx_samples[0], g_signed_trx_samples[1]};
  thc1->getSpecificHandler<network::tarcap::TransactionPacketHandler>()->onNewTransactions(
      SharedTransactions(transactions));
  SharedTransactions transactions2;
  thc1->getSpecificHandler<network::tarcap::TransactionPacketHandler>()->onNewTransactions(std::move(transactions2));
  thc1->getSpecificHandler<network::tarcap::DagBlockPacketHandler>()->onNewBlockReceived(DagBlock(blk));

  SharedTransactions transactions_to_send;
  transactions_to_send.push_back(g_signed_trx_samples[0]);
  transactions_to_send.push_back(g_signed_trx_samples[1]);
  for (int i = 0; i < nodeCount; i++) {
    thc1->getSpecificHandler<network::tarcap::TransactionPacketHandler>()->sendTransactions(
        thc1->getPeersState()->getPeer(vHosts[i]->id()), std::move(transactions_to_send));
  }
  for (int i = 0; i < 50; i++) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    bool synced = true;
    for (int j = 0; j < nodeCount; j++)
      if (vCapabilities[j]->test_state_->getBlocks().size() == 0) {
        synced = false;
      }
    if (synced) break;
  }
  auto blocks1 = thc1->test_state_->getBlocks();
  for (int i = 0; i < nodeCount; i++) {
    EXPECT_EQ(vCapabilities[i]->test_state_->getBlocks().size(), 1);
    if (vCapabilities[i]->test_state_->getBlocks().size() == 1) {
      EXPECT_EQ(vCapabilities[i]->test_state_->getBlocks().begin()->second, blk);
      EXPECT_EQ(vCapabilities[i]->test_state_->getBlocks().begin()->second.getHash(), blk.getHash());
    }
    auto rtransactions = vCapabilities[i]->test_state_->getTransactions();
    EXPECT_EQ(rtransactions.size(), 2);
    if (rtransactions.size() == 2) {
      EXPECT_EQ(*transactions[0], *rtransactions[g_signed_trx_samples[0]->getHash()]);
      EXPECT_EQ(*transactions[1], *rtransactions[g_signed_trx_samples[1]->getHash()]);
    }
  }
  EXPECT_EQ(blocks1.size(), 1);
  if (blocks1.size()) {
    EXPECT_EQ(blk, blocks1.begin()->second);
  }
}

TEST_F(P2PTest, multiple_capabilities) {
  auto node_cfgs = make_node_cfgs(3);
  h256 genesis_hash;
  NetworkConfig network_conf;
  network_conf.transaction_interval_ms = 1000;
  auto cleanup = []() {
    std::filesystem::remove_all("/tmp/nw2");
    std::filesystem::remove_all("/tmp/nw3");
  };
  auto wait_for_connection = [](std::shared_ptr<Network> nw1, std::shared_ptr<Network> nw2) {
    EXPECT_HAPPENS({15s, 500ms}, [&](auto &ctx) {
      nw1->setPendingPeersToReady();
      nw2->setPendingPeersToReady();
      WAIT_EXPECT_EQ(ctx, nw1->getPeerCount(), 1)
      WAIT_EXPECT_EQ(ctx, nw2->getPeerCount(), 1)
    });
  };
  const auto kp1 = KeyPair::create();
  const auto kp2 = KeyPair::create();
  cleanup();
  {
    auto nw1 = std::make_shared<taraxa::Network>(
        node_cfgs[0], genesis_hash,
        [kp1, &node_cfgs, &genesis_hash](auto host) {
          auto cap = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 3);
          return Host::CapabilityList{cap};
        },
        "/tmp/nw2");
    auto nw2 = std::make_shared<taraxa::Network>(
        node_cfgs[1], genesis_hash,
        [kp2, &node_cfgs, &genesis_hash](auto host) {
          auto cap = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 3);
          return Host::CapabilityList{cap};
        },
        "/tmp/nw3");
    nw1->start();
    nw2->start();
    wait_for_connection(nw1, nw2);
  }
  cleanup();
  {
    auto nw1 = std::make_shared<taraxa::Network>(
        node_cfgs[0], genesis_hash,
        [kp1, &node_cfgs, &genesis_hash](auto host) {
          auto cap1 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 1);
          auto cap2 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 2);
          auto cap3 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 3);
          return Host::CapabilityList{cap1, cap2, cap3};
        },
        "/tmp/nw2");
    auto nw2 = std::make_shared<taraxa::Network>(
        node_cfgs[1], genesis_hash,
        [kp2, &node_cfgs, &genesis_hash](auto host) {
          auto cap1 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 1);
          auto cap2 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 2);
          auto cap3 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 3);
          return Host::CapabilityList{cap1, cap2, cap3};
        },
        "/tmp/nw3");
    nw1->start();
    nw2->start();
    wait_for_connection(nw1, nw2);
  }
  cleanup();
  {
    auto nw1 = std::make_shared<taraxa::Network>(
        node_cfgs[0], genesis_hash,
        [kp1, &node_cfgs, &genesis_hash](auto host) {
          auto cap1 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 1);
          auto cap2 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 2);
          auto cap3 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 3);
          return Host::CapabilityList{cap1, cap2, cap3};
        },
        "/tmp/nw2");
    auto nw2 = std::make_shared<taraxa::Network>(
        node_cfgs[1], genesis_hash,
        [kp2, &node_cfgs, &genesis_hash](auto host) {
          auto cap2 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 2);
          auto cap3 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 3);
          auto cap4 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 4);
          return Host::CapabilityList{cap2, cap3, cap4};
        },
        "/tmp/nw3");
    nw1->start();
    nw2->start();
    wait_for_connection(nw1, nw2);
  }
  cleanup();
  {
    auto nw1 = std::make_shared<taraxa::Network>(
        node_cfgs[0], genesis_hash,
        [kp1, &node_cfgs, &genesis_hash](auto host) {
          auto cap1 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 1);
          auto cap2 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 2);
          auto cap3 = network::tarcap::TaraxaCapability::make(host, kp1, node_cfgs[0], genesis_hash, 3);
          return Host::CapabilityList{cap1, cap2, cap3};
        },
        "/tmp/nw2");
    auto nw2 = std::make_shared<taraxa::Network>(
        node_cfgs[1], genesis_hash,
        [kp2, &node_cfgs, &genesis_hash](auto host) {
          auto cap4 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 4);
          auto cap5 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 5);
          auto cap6 = network::tarcap::TaraxaCapability::make(host, kp2, node_cfgs[1], genesis_hash, 6);
          return Host::CapabilityList{cap4, cap5, cap6};
        },
        "/tmp/nw3");
    nw1->start();
    nw2->start();

    // check that connection wasn't established
    std::this_thread::sleep_for(5s);
    EXPECT_EQ(nw1->getPeerCount(), 0);
    EXPECT_EQ(nw2->getPeerCount(), 0);
  }
}

}  // namespace taraxa::core_tests

using namespace taraxa;
int main(int argc, char **argv) {
  static_init();
  auto logging = logger::createDefaultLoggingConfig();
  logging.verbosity = logger::Verbosity::Error;

  addr_t node_addr;
  logger::InitLogging(logging, node_addr);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
