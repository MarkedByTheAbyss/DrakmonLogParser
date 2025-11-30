#pragma once

#include <fstream>
#include <string>
#include <map>
#include <vector>

#include "json.hpp"
#include "../src/functions.cpp"

using json = nlohmann::json;
using string = std::string;
using uint = unsigned int;

class Ruleset
{
public:

	typedef std::map<uint, std::map<uint, std::vector<string>>> RulesetMap;

public:

	Ruleset() = default;
	~Ruleset() = default;

	int LoadRules(string filename);
	std::vector<string> GetRuleFields(string plugin, string method) const;

private:

	void InsertRule(const json& rule);

	template<class T>
	inline std::optional<T> GetOptVal(const json& json, const string& key)
	{
		try
		{
			if (json.contains(key))
				return json[key].get<T>();
		}
		JSONCATCH();
		return std::nullopt;
	}

private:

	RulesetMap m_RulesetMap;

};

