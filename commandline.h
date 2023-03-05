#include <mutex>
#include <vector>
#include <string>
#include <iostream>

class CommandLineInput
{
	std::string status;
	std::string trim(std::string& str);
	size_t split(std::string&, std::vector<std::string>&, char);

public:
	CommandLineInput(std::string);
	void commandLineLoop();
};
