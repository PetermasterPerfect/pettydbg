#include "unicodeStringEx.h"

UnicodeStringEx::~UnicodeStringEx()
{
	delete realUnicode.Buffer;
}

UnicodeStringEx::UnicodeStringEx(HANDLE h, PUNICODE_STRING buf)
{
	WCHAR *wstrBuf = new WCHAR[buf->Length+1];
	if(wstrBuf == nullptr)
		return;

	memset(wstrBuf, 0, sizeof(WCHAR) * (buf->Length + 1));
	if(!ReadProcessMemory(h, buf->Buffer, wstrBuf, buf->Length, NULL))
	{
		std::cerr << "UnicodeStringEx ReadProcessMemory2 failed " << GetLastError() << std::endl;
		return;
	}
	realUnicode.Length = buf->Length;
	realUnicode.MaximumLength = buf->MaximumLength;
	realUnicode.Buffer = wstrBuf;
}

std::string UnicodeStringEx::toString()
{
	std::wstring buf(realUnicode.Buffer);
	std::string ret(buf.begin(), buf.end());
	return ret;
}