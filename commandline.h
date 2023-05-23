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

	std::string status;
	std::vector<std::string> arguments;
	std::atomic<bool> cmdToHandle;
	void printCommandPrompt();
	
	
	std::string trim(std::string& str);
public:
	CommandLineInput(std::string);
	void commandLineInterface();
};
