/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_DEV_RPC_ADMINTARAXAFACE_H_
#define JSONRPC_CPP_STUB_DEV_RPC_ADMINTARAXAFACE_H_

#include "ModularServer.h"

namespace dev {
    namespace rpc {
        class AdminTaraxaFace : public ServerInterface<AdminTaraxaFace>
        {
            public:
                AdminTaraxaFace()
                {
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_blockQueueStatus", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_blockQueueStatusI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_setAskPrice", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_setAskPriceI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_setBidPrice", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_setBidPriceI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_setMining", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_BOOLEAN,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_setMiningI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_findBlock", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_findBlockI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_blockQueueFirstUnknown", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_STRING, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_blockQueueFirstUnknownI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_blockQueueRetryUnknown", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_blockQueueRetryUnknownI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_allAccounts", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_ARRAY, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_allAccountsI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_newAccount", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_OBJECT,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_newAccountI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_setMiningBenefactor", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_setMiningBenefactorI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_inspect", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_inspectI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_reprocess", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_reprocessI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_vmTrace", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_INTEGER,"param3",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_vmTraceI);
                    this->bindAndAddMethod(jsonrpc::Procedure("admin_taraxa_getReceiptByHashAndIndex", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_INTEGER,"param3",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::admin_taraxa_getReceiptByHashAndIndexI);
                    this->bindAndAddMethod(jsonrpc::Procedure("miner_start", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_INTEGER, NULL), &dev::rpc::AdminTaraxaFace::miner_startI);
                    this->bindAndAddMethod(jsonrpc::Procedure("miner_stop", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN,  NULL), &dev::rpc::AdminTaraxaFace::miner_stopI);
                    this->bindAndAddMethod(jsonrpc::Procedure("miner_setEtherbase", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::miner_setEtherbaseI);
                    this->bindAndAddMethod(jsonrpc::Procedure("miner_setExtra", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::miner_setExtraI);
                    this->bindAndAddMethod(jsonrpc::Procedure("miner_setGasPrice", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING, NULL), &dev::rpc::AdminTaraxaFace::miner_setGasPriceI);
                    this->bindAndAddMethod(jsonrpc::Procedure("miner_hashrate", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_STRING,  NULL), &dev::rpc::AdminTaraxaFace::miner_hashrateI);
                }

                inline virtual void admin_taraxa_blockQueueStatusI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_blockQueueStatus(request[0u].asString());
                }
                inline virtual void admin_taraxa_setAskPriceI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_setAskPrice(request[0u].asString(), request[1u].asString());
                }
                inline virtual void admin_taraxa_setBidPriceI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_setBidPrice(request[0u].asString(), request[1u].asString());
                }
                inline virtual void admin_taraxa_setMiningI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_setMining(request[0u].asBool(), request[1u].asString());
                }
                inline virtual void admin_taraxa_findBlockI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_findBlock(request[0u].asString(), request[1u].asString());
                }
                inline virtual void admin_taraxa_blockQueueFirstUnknownI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_blockQueueFirstUnknown(request[0u].asString());
                }
                inline virtual void admin_taraxa_blockQueueRetryUnknownI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_blockQueueRetryUnknown(request[0u].asString());
                }
                inline virtual void admin_taraxa_allAccountsI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_allAccounts(request[0u].asString());
                }
                inline virtual void admin_taraxa_newAccountI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_newAccount(request[0u], request[1u].asString());
                }
                inline virtual void admin_taraxa_setMiningBenefactorI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_setMiningBenefactor(request[0u].asString(), request[1u].asString());
                }
                inline virtual void admin_taraxa_inspectI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_inspect(request[0u].asString(), request[1u].asString());
                }
                inline virtual void admin_taraxa_reprocessI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_reprocess(request[0u].asString(), request[1u].asString());
                }
                inline virtual void admin_taraxa_vmTraceI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_vmTrace(request[0u].asString(), request[1u].asInt(), request[2u].asString());
                }
                inline virtual void admin_taraxa_getReceiptByHashAndIndexI(const Json::Value &request, Json::Value &response)
                {
                    response = this->admin_taraxa_getReceiptByHashAndIndex(request[0u].asString(), request[1u].asInt(), request[2u].asString());
                }
                inline virtual void miner_startI(const Json::Value &request, Json::Value &response)
                {
                    response = this->miner_start(request[0u].asInt());
                }
                inline virtual void miner_stopI(const Json::Value &request, Json::Value &response)
                {
                    (void)request;
                    response = this->miner_stop();
                }
                inline virtual void miner_setEtherbaseI(const Json::Value &request, Json::Value &response)
                {
                    response = this->miner_setEtherbase(request[0u].asString());
                }
                inline virtual void miner_setExtraI(const Json::Value &request, Json::Value &response)
                {
                    response = this->miner_setExtra(request[0u].asString());
                }
                inline virtual void miner_setGasPriceI(const Json::Value &request, Json::Value &response)
                {
                    response = this->miner_setGasPrice(request[0u].asString());
                }
                inline virtual void miner_hashrateI(const Json::Value &request, Json::Value &response)
                {
                    (void)request;
                    response = this->miner_hashrate();
                }
                virtual Json::Value admin_taraxa_blockQueueStatus(const std::string& param1) = 0;
                virtual bool admin_taraxa_setAskPrice(const std::string& param1, const std::string& param2) = 0;
                virtual bool admin_taraxa_setBidPrice(const std::string& param1, const std::string& param2) = 0;
                virtual bool admin_taraxa_setMining(bool param1, const std::string& param2) = 0;
                virtual Json::Value admin_taraxa_findBlock(const std::string& param1, const std::string& param2) = 0;
                virtual std::string admin_taraxa_blockQueueFirstUnknown(const std::string& param1) = 0;
                virtual bool admin_taraxa_blockQueueRetryUnknown(const std::string& param1) = 0;
                virtual Json::Value admin_taraxa_allAccounts(const std::string& param1) = 0;
                virtual Json::Value admin_taraxa_newAccount(const Json::Value& param1, const std::string& param2) = 0;
                virtual bool admin_taraxa_setMiningBenefactor(const std::string& param1, const std::string& param2) = 0;
                virtual Json::Value admin_taraxa_inspect(const std::string& param1, const std::string& param2) = 0;
                virtual Json::Value admin_taraxa_reprocess(const std::string& param1, const std::string& param2) = 0;
                virtual Json::Value admin_taraxa_vmTrace(const std::string& param1, int param2, const std::string& param3) = 0;
                virtual Json::Value admin_taraxa_getReceiptByHashAndIndex(const std::string& param1, int param2, const std::string& param3) = 0;
                virtual bool miner_start(int param1) = 0;
                virtual bool miner_stop() = 0;
                virtual bool miner_setEtherbase(const std::string& param1) = 0;
                virtual bool miner_setExtra(const std::string& param1) = 0;
                virtual bool miner_setGasPrice(const std::string& param1) = 0;
                virtual std::string miner_hashrate() = 0;
        };

    }
}
#endif //JSONRPC_CPP_STUB_DEV_RPC_ADMINTARAXAFACE_H_