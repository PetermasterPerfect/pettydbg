#include "unicodeStringEx.h"

UnicodeStringEx::~UnicodeStringEx()
{
	delete actualString.Buffer;
}

UnicodeStringEx::UnicodeStringEx(HANDLE h, PUNICODE_STRING buf)
{
	PWSTR strBuf;
	strBuf = new wchar_t[buf->Length];
	if(strBuf == nullptr)
		return;

	if(!ReadProcessMemory(h, buf->Buffer, strBuf, buf->Length, NULL))
	{
		std::cerr << "UnicodeStringEx ReadProcessMemory2 failed " << GetLastError() << std::endl;
		return;
	}
	actualString.Length = buf->Length;
	actualString.MaximumLength = buf->MaximumLength;
	actualString.Buffer = strBuf;
}

std::string UnicodeStringEx::toString()
{
	char *s = new char[actualString.Length+2];
	memmove(s, actualString.Buffer, actualString.Length);
	*(short*)(&s[actualString.Length]) = 0;
	std::wstring buf((wchar_t*)s);
	std::string ret(buf.begin(), buf.end());
	return ret;
}