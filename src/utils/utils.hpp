#pragma once

#include <sstream>
#include <vector>
#include <chrono>
#include <regex>

#include <windows.h>

namespace utils {

    namespace console {

        bool is_windows() {
#ifdef _WIN32
            return true;
#endif
            return false;
        }

        bool set_utf8() {

            std::vector<int> err;

            err.push_back(SetConsoleCP(CP_UTF8));
            err.push_back(SetConsoleOutputCP(CP_UTF8));

            if (err[0] || err[1]) { return true; }

            return !system("chcp 65001 > nul");
        }
    }

    namespace get {
        // inclusive [min, max]
        int random_number(int min, int max) {
            static bool first = true;
            if (first) {
                srand(time(NULL));
                first = false;
            }
            return min + rand() % ((max + 1) - min);
        }

        long long milliseconds_since_epoch() {
            return duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        }
    }

    namespace string {
        void match_regex(std::string content, const std::string &pattern, std::vector<std::string> &out) {
            std::regex regexPattern(pattern);
            std::smatch match;

            while (std::regex_search(content, match, regexPattern)) {
                out.push_back(match.str(1));
                content = match.suffix().str();
            }
        }
    }

    namespace conversion {

        void string_to_byte_vector(const std::string &in, std::vector<unsigned char> &out) {
            out = std::vector<unsigned char>(in.begin(), in.end());
        }

        void bytes_array_to_string(const unsigned char *in, size_t len, std::string &out) {
            out = std::string(reinterpret_cast<const char *>(in), len);
        }

        void hexstring_to_string(const std::string &in, std::string &out) {
            std::stringstream str_stream;
            for (size_t i = 0; i < in.length(); i += 2) {
                std::string byte = in.substr(i, 2);
                char chr = (char)(int)strtol(byte.c_str(), nullptr, 16);
                str_stream << chr;
            }
            out = str_stream.str();
        }

        void string_to_hexstring(const std::string &in, std::string &out) {
            std::stringstream str_stream;
            for (const auto &item : in) {
                str_stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(static_cast<uint8_t>(item));
            }
            out = str_stream.str();
        }
    }
}