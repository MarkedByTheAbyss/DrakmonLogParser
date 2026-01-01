#pragma once;
#include <regex>
#include <source_location>
#include <iostream>

#if defined(_WIN32) || defined(_WIN64)
#include <../inc/yara/rules.h>
#else
#include <yara/rules.h>
#endif

#include "../inc/json.hpp"

#define STRHASH Functions::fnv1a_32

#define LOGERR() \
	Functions::LogError(std::source_location::current()) 

#define RETERR() \
	{	\
	std::cout << "Returned with error:\n";	\
	Functions::LogError(std::source_location::current()); \
	return;	\
	} \

#define JSONCATCH() \
	catch(json::exception e) \
	{	\
	};	\

using json = nlohmann::ordered_json;


class Functions
{
public:
	
	struct MatchInfo
	{
		const char* rule;
		const char* string;
	};

	struct CallbackInfo
	{
		std::string parsingPattern;

		json parsedInfo;
		MatchInfo matchInfo;

		void clear()
		{
			parsingPattern.clear();
			parsedInfo.clear();
			matchInfo.rule = nullptr;
			matchInfo.string = nullptr;
		}
	};

public:

	static constexpr unsigned int fnv1a_32(const char* str, unsigned int hash = 2166136261)
	{
		for (; *str; ++str) {
			hash = (hash ^ static_cast<unsigned int>(*str)) * 16777619;
		}
		return hash;
	}

	static void LogError(std::source_location loc)
	{
		std::cout << "Error in:" << loc.file_name() << ":" << loc.line() 
			<< " - " << loc.function_name() << std::endl;
		return;
	}

	static void SetMatchesInfo(CallbackInfo* info, const char* rule, const char* str)
	{
		info->matchInfo.rule = rule;
		info->matchInfo.string = str;
	}

	static void AddParsedData(CallbackInfo* info, std::string parsedData)
	{
		info->parsedInfo["ParsedData"] = parsedData;
	}

	static std::string Parse(YR_SCAN_CONTEXT* context, YR_STRING* str,
		std::regex parsingRegex)
	{
		YR_MATCH* yrMatch;
		yr_string_matches_foreach(context, str, yrMatch)
		{
			if (yrMatch)
			{
				std::string curString((char*)yrMatch->data);
				std::smatch match;
				if (std::regex_search(curString, match, parsingRegex))
				{
					return match.str();
				}
			}
		}
		return "";
	}

};