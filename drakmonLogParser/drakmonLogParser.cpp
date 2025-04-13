#include "drakmonLogParser.h"

void drakmonLogParser::LoadInjectedPID(const json json)
{
	uint injectedPID = GetOptVal<uint>(json, "InjectedPid").value_or(-1);
	m_ProcessTree.SetIntectedPID(injectedPID);

	string FullFilename = GetOptVal<string>(json, "ProcessName").value_or("");
	uint filenameInd = FullFilename.rfind("\\");
	string filename = FullFilename.substr(filenameInd + 1);
	string path = FullFilename.substr(0, filenameInd + 1);

	Process injectedProc(
		injectedPID,
		0,	
		false,
		filename,
		path
	);
	m_ProcessTree.Insert(injectedPID, injectedProc);
}

std::ifstream drakmonLogParser::OpenFile(const string& Filename)
{
	std::ifstream file(Filename);
	return file;
}

void drakmonLogParser::LoadPreInstProcs(const string& Filename)
{
	std::ifstream file = OpenFile(Filename);
	if (not file.is_open())
		return;

	string line;
	while (not file.eof())
	{
		std::getline(file, line);
		json json = Str2Json(line);
		InsertPreInstProcess(json);
	}
	file.close();
}

void drakmonLogParser::FillProcTree(const string& Filename)
{
	std::ifstream file = OpenFile(Filename);
	if (not file.is_open())
		return;

	string line;

	std::getline(file, line);
	LoadInjectedPID(Str2Json(line));

	uint linenum = 1;
	while (not file.eof())
	{
		std::getline(file, line);
		json json = Str2Json(line);
		InsertProcess(json, linenum);
		++linenum;
	}
	file.close();
}

void drakmonLogParser::WriteProcTree()
{
	for (auto& elem : m_ProcessTree.GetTree())
	{
		std::cout << "\"PID\":" << elem.first << ' ' << elem.second << std::endl;
	}
}

json drakmonLogParser::Str2Json(string const Logline) const
{
	json json;
	try
	{
		json = json::parse(Logline);
	}
	catch (const json::exception& e)
	{
		//pohuy
	}
	return json;
}

void drakmonLogParser::InsertProcess(json const json, const uint linenum)
{
	try
	{
		uint PPID = GetOptVal<uint>(json, "PPID").value_or(-1);
		Process* parent = m_ProcessTree.GetProcess(PPID);
		if (parent == nullptr || parent->GetIsPreInstalled() == true)
			return;
		parent->AppendChild(GetOptVal<uint>(json, "PID").value_or(-1));

		uint PID = GetOptVal<uint>(json, "PID").value_or(-1);

		string FullFilename = GetOptVal<string>(json, "ProcessName").value_or("");
		uint filenameInd = FullFilename.rfind("\\");
		string filename = FullFilename.substr(filenameInd + 1);
		string path = FullFilename.substr(0, filenameInd + 1);

		Process newProc(
			PPID,
			linenum,
			CheckPreInstalled({ PID, filename, path }),
			filename,
			path
		);
		m_ProcessTree.Insert(PID, newProc);
	}
	catch (json::exception& e)
	{
		return;
	}
}

void drakmonLogParser::InsertPreInstProcess(json const json)
{
	try
	{
		PreInstalled process =
		{
			GetOptVal<uint>(json, "PID").value_or(-1),
			GetOptVal<string>(json, "ProcessName").value_or(""),
			GetOptVal<string>(json, "Path").value_or("")
		};
		m_PreInstProcs.push_back(process);
	}
	catch (json::exception& e)
	{
		return;
	}
}

bool drakmonLogParser::CheckPreInstalled(PreInstalled proc)
{
	for (auto& e : m_PreInstProcs)
	{
		if (e.PID == proc.PID || (e.Name == proc.Name && e.Path == proc.Path))
			return true;
	}
	return false;
}
