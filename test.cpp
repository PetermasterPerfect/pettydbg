#include <iostream>
#include <sstream>
#include <string>
using namespace std;

int main() {

	std::string buf;
	std::streambuf *backup = std::cin.rdbuf();
    std::istringstream iss("\n");
    std::cin.rdbuf(iss.rdbuf());
	cin>>buf;
	std::cin.rdbuf(backup);
    return 0;
}