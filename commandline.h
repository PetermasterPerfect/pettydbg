#pragma once
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <atomic>
#include <condition_variable>
#include <windows.h>
#include <queue>
#include <thread>
#include "splitstring.h"
//#include "safe_queue.h"

class CommandLineInput
{
protected:
//	SafeQueue<std::string> qCmdRet;
	std::queue<std::string> qDbgMess;
	//std::string dbgMess;
	std::string cmdRet;
	std::mutex mxDbgMess;
	std::mutex mxCmdRet;
	std::mutex mxContinueDebugging;
	std::condition_variable cvCmdRet;

	std::string status;
	std::vector<std::string> arguments;
	std::mutex mxArg;
	std::mutex mxStatus;
	std::atomic<bool> cmdToHandle;
	void handleCmdReturn();
	void handleDbgMessage();
	void waitForBreak();
	
	
	std::string trim(std::string& str);
public:
	CommandLineInput(std::string);
	void commandLineLoop();
};
