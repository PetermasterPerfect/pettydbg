#pragma once
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <mutex>
#include <atomic>
//#include <thread>
#include <windows.h>
#include "splitstring.h"

class CommandLineInput
{
protected:
	std::string status;
	std::vector<std::string> arguments;
	std::mutex argMutex;
	std::mutex statusMutex;
	std::atomic<bool> cmdToHandle;
	
	std::string trim(std::string& str);
public:
	CommandLineInput(std::string);
	void commandLineLoop();
};
