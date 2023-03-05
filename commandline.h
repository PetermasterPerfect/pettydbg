#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include "splitstring.h"

class CommandLineInput
{
	std::string status;
	std::string trim(std::string& str);
	//void split(std::string work, std::vector<std::stringchar delim, int rep=0);
	size_t nearer_whitespace_char(size_t, std::string);

public:
	CommandLineInput(std::string);
	void commandLineLoop();
};
