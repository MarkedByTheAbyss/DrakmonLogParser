#pragma once
#include <fstream>
#include <optional>
#include <yara/rules.h>

#include "json.hpp"
#include "ProcessTree.h"
#include "YaraAnalyzer.h"
#include "functions.cpp"

using json = nlohmann::json;

template<class T>
concept Filestream = std::is_base_of<std::ios, T>::value;

typedef std::map<const char*, uint> RuleMatches;
static RuleMatches m_Matcher;
static json ruleMatches;

struct PreInstalled
{
	uint PID;
	string Name;
	string Path;
};

class drakmonLogParser 
{
public:
	// typedef
	typedef std::vector<PreInstalled> PreInstalledProcs;

public:

	drakmonLogParser() = default;
	~drakmonLogParser() = default;

	void LoadPreInstProcs(const string& Filename);
	void SortProcesses(const string& Filename);
	void WriteProcTree();
	void AnalyzeProcessTree();
	
protected:

	void LoadInjectedPID(const json json);
	json Str2Json(string const Logline) const;
	int InsertProcess(json const Json, const uint linenum);
	void InsertPreInstProcess(json const Json);
	bool CheckPreInstalled(PreInstalled proc);
	int FormRecord(Functions::CallbackData* data);
	int LogFileMatches();
	static int Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData);

	template<Filestream T> 
	T OpenFile(const string& Filename);
	
	template<class T>
	std::optional<T> GetOptVal(json json, const string& key) const;

protected:

	ProcessTree m_ProcessTree;
	PreInstalledProcs m_PreInstProcs;
	YaraAnalyzer* m_Analyzer;

};

template<class T>
inline std::optional<T> drakmonLogParser::GetOptVal(json json, const string& key) const
{
	try
	{
		if (json.contains(key))
			return json[key].get<T>();
	}
	catch (json::exception& e)
	{
	}
	return std::nullopt;
}
