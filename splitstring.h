#pragma once
#include <string>
#include <vector>

class splitstring : public std::string {
	
public:
    std::vector<std::string> flds;
    splitstring(const char *s) : std::string(s) { };
    void split(char, int, std::vector<std::string>&);
};