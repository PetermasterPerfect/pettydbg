#pragma once
#include <string>
#include <iostream>
#include <windows.h>
#include "splitstring.h"
//#include "safe_queue.h"

class CommandLineInput
{
protected:
	std::vector<std::string> arguments;
	bool cmdToHandle;
	void printCommandPrompt();
	
	
	std::string trim(std::string& str);
public:
	void commandLineInterface();
};
