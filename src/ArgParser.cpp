#include "../inc/ArgParser.h"

bool ArgParser::Contains(const std::string& key) const
{
	if (m_ArgMap.contains(key))
		return true;
	return false;
}

std::string ArgParser::Get(const std::string& key)
{
	return m_ArgMap.at(key);
}

void ArgParser::Insert(std::string argument)
{
	int splitInd = argument.find("=");
	std::string key = argument.substr(0, splitInd);
	std::string value = argument.substr(splitInd + 1);
	m_ArgMap.insert({ key,value });
	CheckHelp(key);
}

bool ArgParser::IsHelp() const
{
	return isHelp;
}

void ArgParser::CheckHelp(const std::string& key)
{
	if (key == "-h" ||
		key == "--help" ||
		key == "-help")
		isHelp = true;
}


