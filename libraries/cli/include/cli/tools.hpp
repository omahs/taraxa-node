#pragma once

#include <json/json.h>
#include <libdevcrypto/Common.h>

#include <string>

#include "cli/config.hpp"
#include "common/vrf_wrapper.hpp"

namespace taraxa::cli::tools {

constexpr const char* DEFAULT_TARAXA_DIR_NAME = ".taraxa";
constexpr const char* DEFAULT_TARAXA_DATA_DIR_NAME = ".taraxa/data";
constexpr const char* DEFAULT_WALLET_FILE_NAME = "wallet.json";
constexpr const char* DEFAULT_CONFIG_FILE_NAME = "config.json";
const std::filesystem::path configs_path = std::filesystem::current_path() / "config_jsons";

// Account generation
void generateAccount();
void generateAccount(const dev::KeyPair& account);
void generateAccountFromKey(const std::string& key);

// VRF generation
void generateVrf();
void generateVrf(const taraxa::vrf_wrapper::vrf_sk_t& sk, const taraxa::vrf_wrapper::vrf_pk_t& pk);
void generateVrfFromKey(const std::string& key);

// Generate default config and wallet files
void generateConfig(const std::string& config, cli::Config::NetworkIdType network_id);
Json::Value generateConfig(Config::NetworkIdType network_id);
void generateWallet(const std::string& wallet);

// Override existing config and wallet files
Json::Value overrideConfig(Json::Value& config, std::string& data_dir, std::vector<std::string> boot_nodes,
                           std::vector<std::string> log_channels, std::vector<std::string> log_configurations,
                           const std::vector<std::string>& boot_nodes_append,
                           const std::vector<std::string>& log_channels_append);
Json::Value overrideWallet(Json::Value& wallet, const std::string& node_key, const std::string& vrf_key);

std::string getHomeDir();
std::string getTaraxaDefaultDir();
std::string getTaraxaDataDefaultDir();
std::string getTaraxaDefaultConfigFile();
std::string getWalletDefaultFile();
Json::Value createWalletJson(const dev::KeyPair& account, const taraxa::vrf_wrapper::vrf_sk_t& sk,
                             const taraxa::vrf_wrapper::vrf_pk_t& pk);

}  // namespace taraxa::cli::tools