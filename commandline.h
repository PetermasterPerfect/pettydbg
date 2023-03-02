#include <mutex>

class CommandLineInput
{
	std::string status;
	
public:
	CommandLineInput();
	void commandLineLoop(bool);
};