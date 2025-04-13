#pragma once
#include <fstream>
#include <optional>

#include "json.hpp"
#include "ProcessTree.h"

using json = nlohmann::json;

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
	void FillProcTree(const string& Filename);
	void WriteProcTree();

protected:

	void LoadInjectedPID(const json json);
	std::ifstream OpenFile(const string& Filename);
	json Str2Json(string const Logline) const;
	void InsertProcess(json const Json, const uint linenum);
	void InsertPreInstProcess(json const Json);
	bool CheckPreInstalled(PreInstalled proc);
	
	template<class T>
	std::optional<T> GetOptVal(json json, const string& key) const;

protected:

	ProcessTree m_ProcessTree;
	PreInstalledProcs m_PreInstProcs;

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
