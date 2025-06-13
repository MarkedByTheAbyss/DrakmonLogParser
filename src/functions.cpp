#pragma once;
#include <regex>
#include <source_location>

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

using json = nlohmann::json;


class Functions
{
public:
	
	struct StrMatchCount
	{
		const char* strName;
		unsigned int count;
	};

	typedef std::map<const char*, json> RecordData;
	typedef std::map<const char*, std::vector<StrMatchCount>> MatchCount;
	typedef std::map<const char*, std::vector<int64_t>> LineOffsets;

	struct CallbackData
	{
		RecordData recordData;
		MatchCount matchCount;
		LineOffsets lineOffsets;
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

	static void SetMatchesCount(CallbackData* data, const char* rule, const char* str, unsigned int count)
	{
		if (!data->matchCount.empty() && data->matchCount.contains(rule))
			data->matchCount[rule].push_back({ str, count });
		else
			data->matchCount.insert({ rule, {{ str, count }}});
	}

	static void AddRecordData(CallbackData* data, const char* rule, json ruleString)
	{
		if (data->recordData.contains(rule))
			data->recordData[rule].push_back(ruleString);
		else
			data->recordData[rule] = json::array({ ruleString });
	}

	static std::string GetUrls(YR_SCAN_CONTEXT* context, YR_STRING* str)
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
					return match.str();
				}
			}
		}
	}

	static std::string GetIps(YR_SCAN_CONTEXT* context, YR_STRING* str)
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
					return match.str();
				}
			}
		}
	}

	static void GetMatchJson(CallbackData* data, YR_SCAN_CONTEXT* context, YR_STRING* str)
	{
		YR_MATCH* yrMatch;
		yr_string_matches_foreach(context, str, yrMatch)
		{
			if (!data->lineOffsets.empty() && data->lineOffsets.contains(str->identifier))
				data->lineOffsets[str->identifier].push_back(yrMatch->offset);
			else
				data->lineOffsets.insert({ str->identifier, { yrMatch->offset } });
		}
	}
};