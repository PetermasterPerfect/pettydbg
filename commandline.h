#pragma once
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <windows.h>
#include "splitstring.h"
//#include "safe_queue.h"

class CommandLineInput
{
protected:
//	SafeQueue<std::string> qCmdRet;
//	std::queue<std::string> qDbgMess;
	std::string dbgMess;
	std::string cmdRet;
	std::mutex mDbgMess;
	std::mutex mCmdRet;
	std::condition_variable cvCmdRet;

	std::string status;
	std::vector<std::string> arguments;
	std::mutex argMutex;
	std::mutex statusMutex;
	std::atomic<bool> cmdToHandle;
	void handleCmdReturn();
	void handleDbgMessage();
	
	
	std::string trim(std::string& str);
public:
	CommandLineInput(std::string);
	void commandLineLoop();
};
