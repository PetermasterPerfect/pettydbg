#pragma once
#include <windows.h>
#include <subauth.h>
#include <iostream>
#include <memory>
#include <cstdio>

class UnicodeStringEx
{
public:
	~UnicodeStringEx();
	UnicodeStringEx(HANDLE, PUNICODE_STRING);
	UNICODE_STRING realUnicode;
	std::string toString();
};