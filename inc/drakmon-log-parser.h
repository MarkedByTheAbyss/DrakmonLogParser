#pragma once
#include <fstream>
#include <optional>
#include <filesystem>
#include <string>
#include <algorithm>
#include <cstdint>

#if defined(_WIN32) || defined(_WIN64)
#include <../inc/yara/rules.h>
#include <process.h>
#else
#include <yara/rules.h>
#include <unistd.h>
#endif

#include "json.hpp"
#include "process-tree.h"
#include "yara-analyzer.h"
#include "ruleset.h"

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

class DrakmonLogParser 
{
public:
	// typedef
	typedef std::vector<PreInstalled> PreInstalledProcs;
	typedef std::vector<uint> FileOffsets;

public:

	DrakmonLogParser() = default;
	~DrakmonLogParser() = default;

	void LoadPreInstProcs();
	void SortProcesses();
	void WriteProcTree();
	void AnalyzeProcessTree();
	void AnalyzeProcessTree(bool);

	void SetPreinstPath(const std::string path);
	void SetLogPath(const std::string path);
	void SetRecordDirPath(const std::string path);
	void SetRulesPath(const std::string path);
	void SetSaveMatches(const std::string val);
	
protected:

	void LoadInjectedPID(const json json);
	json Str2Json(string const Logline) const;
	string CreateTempFilePath();
	int InsertProcess(json const Json, const uint linenum);
	void InsertPreInstProcess(json const Json);
	bool CheckPreInstalled(PreInstalled proc);
	int FormRecord(Functions::CallbackData* data);
	json GetJsonByOffset(int64_t offset);
	static int Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData);

	template<Filestream T> 
	T OpenFile(const string& Filename);
	
protected:

	ProcessTree m_ProcessTree;
	PreInstalledProcs m_PreInstProcs;
	FileOffsets m_Offsets;

	string m_PreinstPath;
	string m_LogPath;
	string m_RecordDirPath;
	string m_RulesPath;
	string m_TempLogPath;

	bool m_SaveMatches;

	Ruleset m_Ruleset;

	YaraAnalyzer* m_Analyzer;

};