#pragma once
#ifdef _WIN32
#include <windows.h>
#include <subauth.h>
#include <string>
#include <iostream>

class UnicodeStringEx
{
public:
	UNICODE_STRING realUnicode;
	UnicodeStringEx(HANDLE, PUNICODE_STRING);
	~UnicodeStringEx();
	std::string toString();
};
#endif
