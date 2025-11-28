#pragma once

#include <vector>
#include <map>
#include <iostream>
#include <string>

#include "json.hpp"
#include "../src/functions.cpp"

using string = std::string;
using uint = unsigned int;
using json = nlohmann::json;

/// <summary>
/// 
/// </summary>
class ProcessInfo
{
public:

public:

	ProcessInfo()	= default;
	~ProcessInfo()	= default;

	ProcessInfo(const json& processJson);

	virtual string	GetPlugin()			const;
	virtual uint	GetPID()			const;
	virtual uint	GetParentPID()		const;
	virtual string	GetProcName()		const;
	virtual string	GetMethod()			const;

	json	GetAsJson()			const;

protected:

	string	Plugin;
	uint	PID;
	uint	ParentPID;
	string	ProcessName;
	string	Method;
	string	Status;


};

/// <summary>
/// 
/// </summary>
class ProcessInfoExt : public ProcessInfo
{
public:

	struct DroppedFile
	{
		string Name;
		string Path;
		bool IsStarted;
		uint PID;
	};

	typedef std::vector<DroppedFile> DroppedFiles;
	typedef std::map<string, uint> FoundFlags;
	typedef std::vector<uint> ChildNodes;

	struct ExtraInfo
	{
		bool IsPreInstalled;
		uint LineNumber;
		DroppedFiles DroppedFiles;
		FoundFlags Flags;
		ChildNodes Childs;
	};

public:

	ProcessInfoExt() = default;
	~ProcessInfoExt() = default;

	ProcessInfoExt(const json& processJson);

	bool GetIsPreInstalled()	const;
	uint GetLineNumber()		const;
	json GetAsJsonExt()			const;

	void AddDroppedFile(DroppedFile file);
	void SetFlag(string flagName, uint count);
	void SetLineNumber(uint lineNumber);
	void SetIsPreInstalled(bool isPreInstalled);
	void AppendChild(uint childPID);

protected:

	ExtraInfo	ExtraInfo;

};

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

