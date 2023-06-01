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