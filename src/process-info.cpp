#include "../inc/process-info.h"

ProcessInfo::ProcessInfo(const json& processJson)
{
	this->Plugin		= GetOptVal<string>(processJson, "Plugin").value_or("");
	this->PID			= GetOptVal<uint>(processJson, "PID").value_or(0);
	this->ParentPID		= GetOptVal<uint>(processJson, "PPID").value_or(0);
	this->ProcessName	= GetOptVal<string>(processJson, "ProcessName").value_or("");
	this->Method		= GetOptVal<string>(processJson, "Method").value_or("");
}

uint ProcessInfo::GetPID() const
{
	return this->PID;
}

uint ProcessInfo::GetParentPID() const
{
	return this->ParentPID;
}

string ProcessInfo::GetPlugin() const
{
	return this->Plugin;
}

string ProcessInfo::GetMethod() const
{
	return this->Method;
}

string ProcessInfo::GetProcName() const
{
	return this->ProcessName;
}

json ProcessInfo::GetAsJson() const
{
	json retVal;
	retVal["Plugin"] = this->Plugin;
	retVal["PID"] = this->PID;
	retVal["PPID"] = this->ParentPID;
	retVal["ProcessName"] = this->ProcessName;
	retVal["Method"] = this->Method;
}


/// 
/// 
/// 
ProcessInfoExt::ProcessInfoExt(const json& processJson)
{
	this->Plugin = GetOptVal<string>(processJson, "Plugin").value_or("");
	this->PID = GetOptVal<uint>(processJson, "PID").value_or(0);
	this->ParentPID = GetOptVal<uint>(processJson, "PPID").value_or(0);
	this->ProcessName = GetOptVal<string>(processJson, "ProcessName").value_or("");
	this->Method = GetOptVal<string>(processJson, "Method").value_or("");
}

void ProcessInfoExt::AddDroppedFile(DroppedFile File)
{
	this->ExtraInfo.DroppedFiles.push_back(File);
}

void ProcessInfoExt::SetFlag(string Flagname, uint Count)
{
	this->ExtraInfo.Flags.insert({ Flagname, Count });
}

void ProcessInfoExt::AppendChild(uint ChildPID)
{
	this->ExtraInfo.Childs.push_back(ChildPID);
}

json ProcessInfoExt::GetAsJsonExt() const
{
	json retVal = GetAsJson();
	
	json extraInfo;
	extraInfo["IsPreInstalled"] = GetIsPreInstalled();
	extraInfo["LineNumber"] = GetLineNumber();

	json dropped = json::array();
	for (const auto& e : this->ExtraInfo.DroppedFiles)
		;//dropped.push_back(e);

	json flags = json::array();
	for (const auto& e : this->ExtraInfo.Flags)
		flags[e.first] = e.second;

	json childs = json::array();
	for (const auto& e : this->ExtraInfo.Childs)
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

bool ProcessInfoExt::GetIsPreInstalled() const
{
	return this->ExtraInfo.IsPreInstalled;
}

uint ProcessInfoExt::GetLineNumber() const
{
	return this->ExtraInfo.LineNumber;
}

void ProcessInfoExt::SetLineNumber(uint lineNumber)
{
	this->ExtraInfo.LineNumber = lineNumber;
}

void ProcessInfoExt::SetIsPreInstalled(bool isPreInstalled)
{
	this->ExtraInfo.IsPreInstalled = isPreInstalled;
}