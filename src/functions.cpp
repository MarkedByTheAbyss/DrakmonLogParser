#pragma once;
#include <regex>
#include <../inc/yara/rules.h>

#include "../inc/json.hpp"

#define STRHASH Functions::fnv1a_32
using json = nlohmann::json;


class Functions
{
public:
	typedef std::map<std::string, std::vector<string>> CallbackData;

public:

	static constexpr unsigned int fnv1a_32(const char* str, unsigned int hash = 2166136261)
	{
		for (; *str; ++str) {
			hash = (hash ^ static_cast<unsigned int>(*str)) * 16777619;
		}
		return hash;
	}

	static void AddToRecord(string key, string value, CallbackData* callbackData)
	{
		if (!callbackData->empty() && callbackData->contains(key))
			callbackData->at(key).push_back(value);
		else
			callbackData->insert({ key, { value } });
	}

	static void GetUrls(YR_SCAN_CONTEXT* context, YR_STRING* str, CallbackData* callbackData)
	{
		YR_MATCH* yrMatch;
		yr_string_matches_foreach(context, str, yrMatch)
		{
			if (yrMatch)
			{
				std::string curString((char*)yrMatch->data);
				int offset = curString.find("Arguments\":") + strlen("Arguments\":");
				curString = curString.substr(offset, yrMatch->match_length);
				const char* regex = R"((http(s?):\/\/)?[a-zA-Z0-9\.\-_]+(\.[a-zA-Z]{2,6})+(\/[a-zA-Z0-9_\-\.\/\?\%\#\&\=]*)?)";
				std::regex reg(regex);
				std::smatch match;
				if (std::regex_search(curString, match, reg))
				{
					AddToRecord("URL", match.str(), callbackData);
				}
			}
		}
	}

	static void GetIps(YR_SCAN_CONTEXT* context, YR_STRING* str, CallbackData* callbackData)
	{
		YR_MATCH* yrMatch;
		yr_string_matches_foreach(context, str, yrMatch)
		{
			if (yrMatch)
			{
				std::string curString((char*)yrMatch->data);
				const char* regex = R"(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})";
				std::regex reg(regex);
				std::smatch match;
				if (std::regex_search(curString, match, reg))
				{
					AddToRecord("IP", match.str(), callbackData);
				}
			}
		}
	}

	static json GetMatchJson(YR_SCAN_CONTEXT* context, YR_STRING* str)
	{
		json matches = json::array();
		YR_MATCH* yrMatch;
		yr_string_matches_foreach(context, str, yrMatch)
		{
			std::string curString((char*)yrMatch->data);
			matches.insert(matches.end(), curString);
		}
		
		return json::array({ matches });
	}
};