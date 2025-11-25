#include "../inc/drakmon-log-parser.h"


#if defined(_WIN32) || defined(_WIN64)
    #define GET_PID() _getpid()
#else
    #define GET_PID() getpid()
#endif

void drakmonLogParser::LoadInjectedPID(const json json)
{
	uint injectedPID = GetOptVal<uint>(json, "InjectedPid").value_or(-1);
	m_ProcessTree.SetInjectedPID(injectedPID);

	string fullFilename = GetOptVal<string>(json, "ProcessName").value_or("");
	uint filenameInd = fullFilename.rfind("\\");
	string filename = fullFilename.substr(filenameInd + 1);
	string path = fullFilename.substr(0, filenameInd + 1);

	Process injectedProc(
		injectedPID,
		0,	
		false,
		fullFilename,
		path
	);
	m_ProcessTree.Insert(injectedPID, injectedProc);
}

template<Filestream T> 
T drakmonLogParser::OpenFile(const string& Filename)
{
	T file(Filename);
	return file;
}

std::string drakmonLogParser::CreateTempFilePath()
{
	namespace fs = std::filesystem;
	std::string filename;

	do {
		filename = fs::temp_directory_path().string() + "/temp_drakmon_" + std::to_string(GET_PID()) + std::to_string(rand()) + ".log";
	} while (fs::exists(filename));
	return filename;
}

void drakmonLogParser::LoadPreInstProcs()
{
	std::ifstream file = OpenFile<std::ifstream>(m_PreinstPath);
	if (not file.is_open()) RETERR();
	string line;
	while (not file.eof())
	{
		std::getline(file, line);
		json json = Str2Json(line);
		InsertPreInstProcess(json);
	}
	file.close();
}

void drakmonLogParser::SortProcesses()
{
	std::ifstream file = OpenFile<std::ifstream>(m_LogPath);
	if (not file.is_open()) RETERR();

	m_TempLogPath = CreateTempFilePath();
	std::ofstream sortedLogFile = OpenFile<std::ofstream>(m_TempLogPath);
	if (not sortedLogFile.is_open()) RETERR();

	string line;

	std::getline(file, line);
	LoadInjectedPID(Str2Json(line));

	m_Offsets.push_back(0);
	uint linenum = 1;
	while (not file.eof())
	{
		std::getline(file, line);
		json json = Str2Json(line);
		if (InsertProcess(json, linenum) == 0)
		{
			sortedLogFile << line + '\n';
			m_Offsets.push_back(sortedLogFile.tellp());
		}
		++linenum;
	}
	file.close();
	sortedLogFile.close();
}

void drakmonLogParser::WriteProcTree()
{
	for (auto& elem : m_ProcessTree.GetTree())
	{
		std::cout << "\"PID\":" << elem.first << ' ' << elem.second << std::endl;
	}
}

void drakmonLogParser::AnalyzeProcessTree()
{
	std::ifstream sortedLogFile = OpenFile<std::ifstream>(m_TempLogPath);
	if (not sortedLogFile.is_open()) RETERR();
	
	m_Analyzer = new YaraAnalyzer();
	if (m_Analyzer->Initilalize() != 0) RETERR();

	if (m_Analyzer->LoadRules(m_RulesPath.data()) != 0) RETERR();

	m_Analyzer->SetCallback(Callback);

	sortedLogFile.close();
	Functions::CallbackData userData;
	m_Analyzer->Scan(m_TempLogPath.c_str(), 0, &userData);

	FormRecord(&userData);

	std::remove(m_TempLogPath.c_str());
	return;
}

json drakmonLogParser::Str2Json(string const Logline) const
{
	json json;
	try
	{
		json = json::parse(Logline);
	}
	JSONCATCH();
	return json;
}

int drakmonLogParser::InsertProcess(json const json, const uint linenum)
{
	try
	{
		uint pid = GetOptVal<uint>(json, "PID").value_or(-1);
		if (m_ProcessTree.Contains(pid))
			return 0;

		uint ppid = GetOptVal<uint>(json, "PPID").value_or(-1);
		Process* parent = m_ProcessTree.GetProcess(ppid);
		if (parent == nullptr || parent->GetIsPreInstalled() == true)
			return 1;

		parent->AppendChild(GetOptVal<uint>(json, "PID").value_or(-1));
		string fullFilename = GetOptVal<string>(json, "ProcessName").value_or("");
		uint filenameInd = fullFilename.rfind("\\");
		string filename = fullFilename.substr(filenameInd + 1);
		string path = fullFilename.substr(0, filenameInd + 1);

		Process newProc(
			ppid,
			linenum,
			CheckPreInstalled({ pid, filename, path }),
			filename,
			path
		);
		m_ProcessTree.Insert(pid, newProc);
		return 0;
	}
	catch (json::exception& e)
	{
		return 2;
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

int drakmonLogParser::FormRecord(Functions::CallbackData* data)
{
	if (!std::filesystem::is_directory(m_RecordDirPath))
		std::filesystem::create_directories(m_RecordDirPath);

	std::ofstream recordFile = OpenFile<std::ofstream>(m_RecordDirPath + "record.json");
	if (!recordFile.is_open())
	{
		LOGERR();
		return 1;
	}
	std::ofstream matchesFile;
	if (m_SaveMatches)
	{
		matchesFile = OpenFile<std::ofstream>(m_RecordDirPath + "savedMatches.json");
		if (!matchesFile.is_open())
		{
			LOGERR();
			return 1;
		}
	}

	recordFile << '{' << std::endl;
	for (const auto& elem : data->matchCount)
	{
		json ruleJson;
		json ruleStrings = json::array();
		int ruleCount = 0;
		for (const auto& strMatchCount : elem.second)
		{
			json strJson;
			strJson["String"] = strMatchCount.strName;
			strJson["Count"] = strMatchCount.count;
			ruleCount += strMatchCount.count;
			if (data->lineOffsets.contains(strMatchCount.strName))
			{
				json matchInfo = json::array();
				for (const auto& offset : data->lineOffsets[strMatchCount.strName])
				{
					json logLine = GetJsonByOffset(offset);
					if (not logLine.empty())
					{
						if (m_SaveMatches)
							matchesFile << logLine << std::endl;
						json logLineInfo;
						logLineInfo["PID"] = GetOptVal<uint>(logLine, "PID").value_or(-1);
						logLineInfo["PPID"] = GetOptVal<uint>(logLine, "PPID").value_or(-1);
						string procName = GetOptVal<std::string>(logLine, "ProcessName").value_or("");
						if (!procName.empty())
							logLineInfo["ProcessName"] = procName.substr(procName.rfind('\\') + 1);
						logLineInfo["Method"] = GetOptVal<std::string>(logLine, "Method").value_or("");
						matchInfo += logLineInfo;
					}
				}
				strJson["Matches"] = matchInfo;
			}
			ruleStrings += strJson;
		}
		ruleJson["Rule"] = elem.first;
		ruleJson["Strings"] = ruleStrings;
		ruleJson["Count"] =  ruleCount;
		if (not data->recordData[elem.first].empty())
			ruleJson["Data"] = data->recordData[elem.first];
		recordFile << ruleJson << std::endl;
		ruleCount = 0;
	}
	recordFile << '}' << std::endl;

	recordFile.close();
	if (m_SaveMatches)
		matchesFile.close();
	return 0;
}

json drakmonLogParser::GetJsonByOffset(int64_t offset)
{
	std::ifstream file = OpenFile<std::ifstream>(m_TempLogPath);
	if (not file.is_open())
	{
		LOGERR();
		return NULL;
	}

	if (not m_Offsets.empty())
	{
		uint curOffsetInd = std::lower_bound(m_Offsets.begin(), m_Offsets.end(), offset) - m_Offsets.begin();
		file.seekg(m_Offsets[curOffsetInd-1]);

		string line;
		std::getline(file, line);
		file.close();
		return Str2Json(line);
	}
	return NULL;	
}

int drakmonLogParser::Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData)
{
	YR_RULE* actRule = static_cast<YR_RULE*>(messageData);
	if (actRule && message == CALLBACK_MSG_RULE_MATCHING)
	{
		Functions::CallbackData* callbackData = static_cast<Functions::CallbackData*>(userData);
		YR_STRING* str;
		yr_rule_strings_foreach(actRule, str)
		{
			if (str)
			{
				uint count = context->matches[str->idx].count;
				Functions::SetMatchesCount(callbackData, actRule->identifier, str->identifier, count);

				json ruleString;
				const char* tag;
				yr_rule_tags_foreach(actRule, tag)
				{
					switch (STRHASH(tag))
					{
					case STRHASH("URL"):
						ruleString["URL"] = Functions::GetUrls(context, str);
						break;

					case STRHASH("IP"):
						ruleString["IP"] = Functions::GetIps(context, str);
						break;

					case STRHASH("SaveMatch"):
						Functions::GetMatchJson(callbackData, context, str);
						break;

					default:
						break;
					}
				}
				if (!ruleString.empty())
					Functions::AddRecordData(callbackData, actRule->identifier, ruleString);
			}
		}
	}
	return CALLBACK_CONTINUE;
}

void drakmonLogParser::SetPreinstPath(const std::string path)
{
	m_PreinstPath = path;
}

void drakmonLogParser::SetLogPath(const std::string path)
{
	m_LogPath = path;
}

void drakmonLogParser::SetRecordDirPath(const std::string path)
{
	m_RecordDirPath = path;
}

void drakmonLogParser::SetRulesPath(const std::string path)
{
	m_RulesPath = path;
}

void drakmonLogParser::SetSaveMatches(const std::string val)
{
	m_SaveMatches = std::stoi(val);
}
