#include "commadline.h"

CommandLineInput::CommandLineInput()
{
	isCommandReady.lock();
}

void CommandLineInput::commandLineLoop(bool isAttached)
{
	std::string cmd;
	std::cout << "(" << status << ") >>>";
	std::getline(std::cin, cmd);
	
}