#include "commandline.h"

CommandLineInput::CommandLineInput(std::string st) : cmdToHandle(false)
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
	std::string cmd;
	while(status!="exit")
    {
		statusMutex.lock();
		argMutex.lock();
        std::cout << "(" << status << ") >>>";
        std::getline(std::cin, cmd);
        trim(cmd);
		splitstring extraCmd(cmd.c_str());
		//arguments.clean();
		extraCmd.split(' ', 0, arguments);
		if(arguments.size() > 0)
			cmdToHandle = true;
		argMutex.unlock();
		statusMutex.unlock();
    }
}
