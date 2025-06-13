#pragma once
#include <fstream>
#include <optional>
#include <filesystem>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
#include <../inc/yara/rules.h>
#else
#include <yara/rules.h>
#endif

#include "json.hpp"
#include "ProcessTree.h"
#include "YaraAnalyzer.h"
#include "../src/functions.cpp"

using json = nlohmann::json;

template<class T>
concept Filestream = std::is_base_of<std::ios, T>::value;

typedef std::map<const char*, uint> RuleMatches;

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

	void LoadPreInstProcs();
	void SortProcesses();
	void WriteProcTree();
	void AnalyzeProcessTree();

	void SetPreinstPath(const std::string path);
	void SetLogPath(const std::string path);
	void SetRecordDirPath(const std::string path);
	void SetRulesPath(const std::string path);
	void SetSaveMatches(const std::string val);
	
protected:

	void LoadInjectedPID(const json json);
	json Str2Json(string const Logline) const;
	int InsertProcess(json const Json, const uint linenum);
	void InsertPreInstProcess(json const Json);
	bool CheckPreInstalled(PreInstalled proc);
	int FormRecord(Functions::CallbackData* data);
	json GetJsonByOffset(int64_t offset);
	static int Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData);

	template<Filestream T> 
	T OpenFile(const string& Filename);
	
	template<class T>
	std::optional<T> GetOptVal(json json, const string& key) const;

protected:

	ProcessTree m_ProcessTree;
	PreInstalledProcs m_PreInstProcs;
	YaraAnalyzer* m_Analyzer;

	string m_PreinstPath;
	string m_LogPath;
	string m_RecordDirPath;
	string m_RulesPath;

	bool m_SaveMatches;

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
