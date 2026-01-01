#pragma once

#include <fstream>
#include <string>
#include <map>
#include <vector>

#include "json.hpp"
#include "../src/functions.cpp"

using json = nlohmann::ordered_json;
using string = std::string;
using regex = std::regex;
using uint = unsigned int;

typedef std::vector<string>	JsonFieldsVector;

class ProcessPipeline
{
public:

	typedef std::map<uint, std::map<uint, JsonFieldsVector>> JsonExtractionRuleset;
	typedef std::map<uint, std::map<uint, string>> RegexParsingPatterns;

public:

	ProcessPipeline() = default;
	~ProcessPipeline() = default;

	int Load(string filename);
	JsonFieldsVector GetExtractionRuleFields(string plugin, string method) const;
	string GetParsingPattern(string plugin, string method) const;

private:

	void Insert(const json& rule);

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

	JsonExtractionRuleset	m_ExtractionRuleset;
	RegexParsingPatterns	m_ParsingPatterns;

};

