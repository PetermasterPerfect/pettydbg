#include "commandline.h"

CommandLineInput::CommandLineInput(std::string st)
{
    status = st;
}
std::string CommandLineInput::trim(std::string& str)
{
    str.erase(str.find_last_not_of(' ')+1);         //suffixing spaces
    str.erase(0, str.find_first_not_of(' '));       //prefixing spaces
    return str;
}

size_t CommandLineInput::split(std::string &txt, std::vector<std::string> &strs, char ch)
{
    size_t pos = txt.find( ch );
    size_t initialPos = 0;
    strs.clear();

    while( pos != std::string::npos ) {
        strs.push_back( txt.substr( initialPos, pos - initialPos ) );
        initialPos = pos + 1;

        pos = txt.find( ch, initialPos );
    }

    strs.push_back( txt.substr( initialPos, std::min( pos, txt.size() ) - initialPos + 1 ) );

    return strs.size();
}
void CommandLineInput::commandLineLoop()
{
    std::vector<std::string> args;
	std::string cmd;
	while(status!="exit")
    {
        std::cout << "(" << status << ") >>>";
        std::getline(std::cin, cmd);
        trim(cmd);
        std::cout << cmd << ".\n";
        std::cout << "sz: " << split(cmd, args, ' ') << "\n";
        for(int i=0; i<args.size(); i++)
            std::cout << i << ":" << args[i] << "\n";
    }
}
