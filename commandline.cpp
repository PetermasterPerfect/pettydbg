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
		waitForBreak();
		mxStatus.lock();
        std::cout << "(" << status << ") >>>";
		mxStatus.unlock();
        std::getline(std::cin, cmd);
        trim(cmd);
		splitstring extraCmd(cmd.c_str());
		//arguments.clean();
		//std::cout << "CMD: " << cmd << "\n";
		mxArg.lock();
		extraCmd.split(' ', 0, arguments);
		if(arguments.size() > 0)
			cmdToHandle = true;
		else
		{
			mxArg.unlock();
			continue;
		}
		mxArg.unlock();
		std::cout << "sz: " << qDbgMess.size() << std::endl;
		handleDbgMessage();
		handleCmdReturn();
    }
}

void CommandLineInput::waitForBreak()
{
	std::unique_lock<std::mutex> lock(mxContinueDebugging);
	mxStatus.lock();
	while(status=="running");
	{
		mxStatus.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		mxStatus.lock();
	}
	mxStatus.unlock();
}

void CommandLineInput::handleDbgMessage()
{
	mxDbgMess.lock();
	while(!qDbgMess.empty())
	{
		std::cout << qDbgMess.front();
		qDbgMess.pop();
	}
	
	mxDbgMess.unlock();
}

void CommandLineInput::handleCmdReturn()
{
	std::unique_lock lock(mxCmdRet);
	while(cmdRet.empty())
		cvCmdRet.wait(lock);
	
	if(cmdRet != "xxx")
		std::cout << cmdRet;
	cmdRet.clear();
	lock.unlock();
	cvCmdRet.notify_one();
}
