#include "../inc/process-info.h"

ProcessInfo::ProcessInfo(const json& processJson, 
	const std::vector<string>& fields, string parsingPattern)
{
	try
	{
		m_ParsingPattern = parsingPattern;
		for (const string& field : fields)
		{
			if (processJson.contains(field))
				m_InfoJson[field] = processJson[field];
		}
	}
	JSONCATCH();
}

uint ProcessInfo::GetParentPID() const
{
	return GetOptVal<uint>(m_InfoJson, "PPID").value_or(-1);
}

uint ProcessInfo::GetPID() const
{
	return GetOptVal<uint>(m_InfoJson, "PID").value_or(-1);
}

//
//string ProcessInfo::GetPlugin() const
//{
//	return this->Plugin;
//}
//
//string ProcessInfo::GetMethod() const
//{
//	return this->Method;
//}

json ProcessInfo::Get() const
{
	return m_InfoJson;
}

void ProcessInfo::AddDroppedFile(DroppedFile File)
{
	this->m_ExtraInfo.DroppedFiles.push_back(File);
}

void ProcessInfo::SetFlag(string Flagname, uint Count)
{
	this->m_ExtraInfo.Flags.insert({ Flagname, Count });
}

void ProcessInfo::AppendChild(uint ChildPID)
{
	this->m_ExtraInfo.Childs.push_back(ChildPID);
}

json ProcessInfo::GetAsJsonExt() const
{
	json retVal = Get();
	
	json extraInfo;
	extraInfo["IsPreInstalled"] = GetIsPreInstalled();
	extraInfo["LineNumber"] = GetLineNumber();

	json dropped = json::array();
	for (const auto& e : this->m_ExtraInfo.DroppedFiles)
		;//dropped.push_back(e);

	json flags = json::array();
	for (const auto& e : this->m_ExtraInfo.Flags)
		flags[e.first] = e.second;

	json childs = json::array();
	for (const auto& e : this->m_ExtraInfo.Childs)
		childs.push_back(e);

	if (not dropped.empty())
		extraInfo["DroppedFiles"] = dropped;
	if (not flags.empty())
		extraInfo["Flags"] = flags;
	if (not childs.empty())
		extraInfo["ChildProcesses"] = childs;

	retVal["ExtraInfo"] = extraInfo;

	return retVal;
}
std::string ProcessInfo::GetParsingPattern() const
{
	return m_ParsingPattern;
}


bool ProcessInfo::GetIsPreInstalled() const
{
	return this->m_ExtraInfo.IsPreInstalled;
}

uint ProcessInfo::GetLineNumber() const
{
	return this->m_ExtraInfo.LineNumber;
}

void ProcessInfo::SetLineNumber(uint lineNumber)
{
	this->m_ExtraInfo.LineNumber = lineNumber;
}

void ProcessInfo::SetIsPreInstalled(bool isPreInstalled)
{
	this->m_ExtraInfo.IsPreInstalled = isPreInstalled;
}