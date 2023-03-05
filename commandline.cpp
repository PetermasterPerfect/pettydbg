#include "commandline.h"

CommandLineInput::CommandLineInput(std::string st)
{
    status = st;
}
std::string CommandLineInput::trim(std::string& str)
{
    str.erase(str.find_last_not_of(' ')+1);         //suffixing spaces
    str.erase(0, str.find_first_not_of(' '));       //prefixing spaces
    return str;
}

void CommandLineInput::commandLineLoop()
{
    std::vector<std::string> args;
	std::string cmd;
	while(status!="exit")
    {
        std::cout << "(" << status << ") >>>";
        std::getline(std::cin, cmd);
        trim(cmd);
		splitstring extraCmd(cmd.c_str());
		extraCmd.split(' ', 0, args);
    }
}
