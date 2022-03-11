// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: 2014-2022 The Monero Project

#include "common/json_util.h"
#include "common/threadpool.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/subaddress_index.h"
#include "file_io_utils.h"
#include "misc_log_ex.h"
#include "string_tools.h"
#include "rapidjson/document.h"

struct Settings {
    std::string primaryAddress;
    std::string secretSpendKey;
    std::string secretViewKey;
    std::string prunedTxHex;
    uint32_t minorIndexMax = 10;
    uint32_t majorIndexMax = UINT32_MAX;
    int threads = 8;
};

// To obtain prunedTxHex:
// curl http://127.0.0.1:18081/get_transactions -d \
// '{"txs_hashes":["TXID_HERE"], "decode_as_json": True, "prune": True}' -H 'Content-Type: application/json' \
// | jq '.txs[0].pruned_as_hex'

void accountSearch(uint32_t begin, uint32_t end, const Settings &settings, hw::device &hwdev, const cryptonote::account_base &account, const cryptonote::transaction &tx, const std::vector<crypto::public_key> &tx_pub_keys, int &res) {
    res = 0;
    for (uint32_t accountIndex = begin; accountIndex < end; accountIndex++) {
        // Generate the public spend keys for the first 35 subaddresses
        const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(account.get_keys(), accountIndex, 0, settings.minorIndexMax);
        // get_subaddress_spend_public_key

        // Iterate over transaction outputs
        for (size_t pk_index = 0; pk_index < tx.vout.size(); pk_index++) {
            // Generate key derivation
            crypto::key_derivation derivation;
            hwdev.generate_key_derivation(tx_pub_keys[pk_index], account.get_keys().m_view_secret_key, derivation);

            // Derive subaddress public spend key
            crypto::public_key subaddressSpendKey;
            hwdev.derive_subaddress_public_key(boost::get<cryptonote::txout_to_key>(tx.vout[pk_index].target).key, derivation, pk_index, subaddressSpendKey);
//            LOG_PRINT_L0("Subaddress spend key: " << subaddressSpendKey);

            // Check if we own spend key
            auto it = std::find(pkeys.begin(), pkeys.end(), subaddressSpendKey);
            if (it != pkeys.end()) {
                LOG_PRINT_L0("Pubkey found! At account index: " << accountIndex << ", minor index: " << std::distance(pkeys.begin(), it) << ", subaddress spend key: " << epee::string_tools::pod_to_hex(*it));
                res = 1;
            }
        }
    }

    LOG_PRINT_L0("Completed task: " << begin << " - " << end);
}

bool loadSettings(std::string filename, Settings &settings) {
    // Load config file from disk
    std::string configBuf;
    bool r = epee::file_io_utils::load_file_to_string(filename, configBuf, UINT32_MAX);
    if (!r) {
        MERROR("Failed to load config.json");
        return false;
    }

    // Parse buffer to rapidjson document
    rapidjson::Document json;
    if (json.Parse(configBuf.c_str()).HasParseError() || !json.IsObject()) {
        MERROR("Unable to parse config.json");
        return false;
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, primaryAddress, std::string, String, true, std::string());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, secretSpendKey, std::string, String, true, std::string());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, secretViewKey, std::string, String, true, std::string());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, prunedTxHex, std::string, String, true, std::string());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, minorIndexMax, uint32_t, Int, false, false);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, majorIndexMax, uint32_t, Int, false, false);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, threads, int, Int, false, false);

    settings.primaryAddress = field_primaryAddress;
    settings.secretSpendKey = field_secretSpendKey;
    settings.secretViewKey = field_secretViewKey;
    settings.prunedTxHex = field_prunedTxHex;
    if (field_minorIndexMax_found) {
        settings.minorIndexMax = field_minorIndexMax;
    }
    if (field_majorIndexMax_found) {
        settings.majorIndexMax = field_majorIndexMax;
    }
    if (field_threads_found) {
        settings.threads = field_threads;
    }

    return true;
}

int main() {
    mlog_set_log_level(1);

    Settings settings;
    bool r = loadSettings("config.json", settings);
    if (!r) {
        return 1;
    }

    LOG_PRINT_L0("Loaded config");

    LOG_PRINT_L0("Primary address: " << settings.primaryAddress);
    LOG_PRINT_L0("Threads: " << settings.threads);

    // Parse the primary address
    cryptonote::address_parse_info info;
    cryptonote::get_account_address_from_str_or_url(info, cryptonote::network_type::MAINNET, settings.primaryAddress);
    cryptonote::account_public_address address = info.address;

    // Parse the secret spend key
    crypto::secret_key spendKey;
    epee::string_tools::hex_to_pod(settings.secretSpendKey, spendKey);

    // Parse the secret view key
    crypto::secret_key viewKey;
    epee::string_tools::hex_to_pod(settings.secretViewKey, viewKey);

    // Create the account from the keys
    cryptonote::account_base account;
    account.create_from_keys(address, spendKey, viewKey);

    // Verify key consistency
    crypto::secret_key second;
    keccak((uint8_t *)&account.get_keys().m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
    sc_reduce32((uint8_t *)&second);
    if (memcmp(second.data,account.get_keys().m_view_secret_key.data, sizeof(crypto::secret_key)) != 0) {
        LOG_PRINT_L0("Non-deterministic wallet, check your keys and primary address");
    }

    // Obtain a reference to the software device
    hw::device &hwdev = account.get_device();

    // Parse the tx hex
    cryptonote::transaction tx;
    cryptonote::blobdata txBlob;
    epee::string_tools::parse_hexstr_to_binbuff(settings.prunedTxHex, txBlob);
    cryptonote::parse_and_validate_tx_base_from_blob(txBlob, tx);

    // Parse tx extra
    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    cryptonote::parse_tx_extra(tx.extra, tx_extra_fields);

    // Setup threadpool
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter(tpool);

    // Get transaction output pubkeys
    std::vector<crypto::public_key> tx_pub_keys;
    for (size_t out = 0; out < tx.vout.size(); out++) {
        cryptonote::tx_extra_pub_key pub_key_field;
        find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, out);
        tx_pub_keys.push_back(pub_key_field.pub_key);
    }

    LOG_PRINT_L0("Running tasks");

    uint32_t accountIndex = 0;
    while (accountIndex < settings.majorIndexMax) {
        std::vector<int> results(settings.threads);
        for (int i = 0; i < settings.threads; i++) {
            tpool.submit(&waiter, boost::bind(&accountSearch, accountIndex, accountIndex + 10000, std::cref(settings), std::ref(hwdev), std::cref(account), std::ref(tx), std::cref(tx_pub_keys), std::ref(results[i])), true);
            accountIndex += 10000;
        }
        waiter.wait();

        auto it = std::find(results.begin(), results.end(), 1);
        if (it != results.end()) {
            LOG_PRINT_L0("Done");
            return 0;
        }
    }

    return 0;
}
