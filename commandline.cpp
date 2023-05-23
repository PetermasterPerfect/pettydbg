#include "commandline.h"

CommandLineInput::CommandLineInput(std::string st) : cmdToHandle(false)
{
    status = st;
}
std::string CommandLineInput::trim(std::string& str) // ***
{
    str.erase(str.find_last_not_of(' ')+1);         //suffixing spaces
    str.erase(0, str.find_first_not_of(' '));       //prefixing spaces
    return str;
}

void CommandLineInput::commandLineInterface()
{
	std::string cmd;
    printCommandPrompt();
    std::getline(std::cin, cmd);
	trim(cmd);
	splitstring extraCmd(cmd.c_str());
	extraCmd.split(' ', 0, arguments);
	if(arguments.size() > 0)
		cmdToHandle = true;
}

void CommandLineInput::printCommandPrompt()
{
	std::cout << ">>> ";
}