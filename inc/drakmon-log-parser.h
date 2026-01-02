#pragma once
#include <fstream>
#include <optional>
#include <filesystem>
#include <string>
#include <algorithm>
#include <cstdint>
#include <sstream>
#include <format>

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

using json = nlohmann::ordered_json;

template<class T>
concept Filestream = std::is_base_of<std::ios, T>::value;

typedef std::map<const char*, uint> RuleMatches;

struct PreInstalled
{
	uint PID;
	string Name;
	bool operator==(PreInstalled proc)
	{
		if (this->PID == proc.PID || this->Name == proc.Name)
			return true;
	}
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
	void BuildProcessTree();
	void WriteProcTree();
	void AnalyzeProcessTree();

	void SetRecordDirPath();
	void SetPreinstPath(const std::string path);
	void SetLogPath(const std::string path);
	void SetYaraRulesPath(const std::string path);
	void SetParsingRulesPath(const std::string path);
	void SetSaveMatches(const std::string val);
	
protected:

	void LoadInjectedPID(const json json);
	json Str2Json(string const Logline) const;
	string CreateTempFilePath();
	int InsertProcess(json const Json, const uint linenum);
	void InsertPreInstProcess(json const Json);
	bool CheckPreInstalled(PreInstalled proc);
	int FormRecord(const json& recordJson);
	void AddRecordData(json& jsonData, const Functions::CallbackInfo& info);
	void SaveDebugInfo();

	static int Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData);

	template<Filestream T> 
	T OpenFile(const string& Filename);
	
protected:

	ProcessTree m_ProcessTree;
	PreInstalledProcs m_PreInstProcs;

	string m_PreinstPath;
	string m_LogPath;
	string m_RecordDirPath;
	string m_YaraPath;
	string m_ParsingRulesPath;
	string m_TempLogPath;

	bool m_SaveMatches;

	ProcessPipeline m_ProcessPipeline;

	YaraAnalyzer* m_Analyzer;

};