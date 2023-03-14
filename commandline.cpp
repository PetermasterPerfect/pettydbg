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

void CommandLineInput::commandLineLoop()
{
	std::string cmd;
	std::string ret;
	while(status!="exit")
    {
		statusMutex.lock();
        std::cout << "(" << status << ") >>>";
		statusMutex.unlock();
        std::getline(std::cin, cmd);
        trim(cmd);
		splitstring extraCmd(cmd.c_str());
		//arguments.clean();
		//std::cout << "CMD: " << cmd << "\n";
		argMutex.lock();
		extraCmd.split(' ', 0, arguments);
		if(arguments.size() > 0)
			cmdToHandle = true;
		else
		{
			argMutex.unlock();
			continue;
		}
		argMutex.unlock();
		handleDbgMessage();
		handleCmdReturn();
    }
}

void CommandLineInput::handleDbgMessage()
{
	mDbgMess.lock();
	if(!dbgMess.empty())
		std::cout << dbgMess;
	dbgMess.clear();
	mDbgMess.unlock();
}

void CommandLineInput::handleCmdReturn()
{
	std::unique_lock lock(mCmdRet);
	while(cmdRet.empty())
		cvCmdRet.wait(lock);
	
	//if(cmdRet != "xxx")
	std::cout << cmdRet;
	cmdRet.clear();
	lock.unlock();
	cvCmdRet.notify_one();
}
