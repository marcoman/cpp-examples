#include "utils.hpp"
#include <fstream>
#include <ctime>

void update_file(std::string filename) {
	std::ofstream file_stream(filename.c_str());
	if (!file_stream) {
		throw std::ios_base::failure("Failed to open file");
	}

	// Get the current time
	std::time_t current_time = std::time(nullptr);
	char time_buffer[100];
	if (std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&current_time))) {
		file_stream << time_buffer;
	} else {
		throw std::runtime_error("Failed to format time");
	}
	if (file_stream.is_open()) file_stream.close();
}