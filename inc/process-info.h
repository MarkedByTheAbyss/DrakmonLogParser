#pragma once

#include <vector>
#include <map>
#include <iostream>
#include <string>

#include "json.hpp"
#include "../src/functions.cpp"

using string = std::string;
using uint = unsigned int;
using json = nlohmann::ordered_json;

/// <summary>
/// 
/// </summary>
class ProcessInfo
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

	ProcessInfo()	= default;
	~ProcessInfo()	= default;

	ProcessInfo(const json& processJson, const std::vector<string>& fields,
		string parsingPattern = "");

	virtual uint GetParentPID()	const;
	virtual uint GetPID()		const;

	//virtual string	GetPlugin()			const;
	//virtual string	GetMethod()			const;

	bool	GetIsPreInstalled()	const;
	uint	GetLineNumber()		const;
	json	GetAsJsonExt()		const;
	string	GetParsingPattern()	const;

	void AddDroppedFile(DroppedFile file);
	void SetFlag(string flagName, uint count);
	void SetLineNumber(uint lineNumber);
	void SetIsPreInstalled(bool isPreInstalled);
	void AppendChild(uint childPID);

	json Get() const;

protected:

	json m_InfoJson;
	ExtraInfo m_ExtraInfo;
	string m_ParsingPattern;

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

