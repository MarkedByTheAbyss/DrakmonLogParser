#pragma once
#include <map>
#include <string>
class ArgParser
{
public:
	typedef std::map<std::string, std::string> ArgMap;

public:

	bool Contains(const std::string& key) const; 
	std::string Get(const std::string& key);
	void Insert(std::string argument);
	bool IsHelp() const;

	ArgParser() : isHelp(false) {};
	~ArgParser() = default;
	
protected:

	void CheckHelp(const std::string& key);

protected:

	ArgMap m_ArgMap;
	bool isHelp;

};

