#include "../inc/drakmon-log-parser.h"


#if defined(_WIN32) || defined(_WIN64)
    #define GET_PID() _getpid()
#else
    #define GET_PID() getpid()
#endif

void DrakmonLogParser::LoadInjectedPID(const json injectedJson)
{
	uint injPID = GetOptVal<uint>(injectedJson, "InjectedPid").value_or(-1);
	m_ProcessTree.SetInjectedPID(injPID);
	string ProcessName = GetOptVal<string>(injectedJson, "ProcessName").value_or("");

	json processJson;
	processJson["PID"] = injPID;
	processJson["ProcessName"] = ProcessName;

	ProcessInfo injInfoExt(processJson, { "PID", "ProcessName" });
	m_ProcessTree.Insert(injPID, injInfoExt);
}

template<Filestream T> 
T DrakmonLogParser::OpenFile(const string& Filename)
{
	T file(Filename);
	return file;
}

void DrakmonLogParser::LoadPreInstProcs()
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

void DrakmonLogParser::BuildProcessTree()
{
	// add rulesPath as member
	m_Ruleset.LoadRules("e:\\GitRepos\\drakmonLogParser\\DrakmonLogParser\\parsing_rules\\rules.json");

	std::ifstream file = OpenFile<std::ifstream>(m_LogPath);
	if (not file.is_open()) RETERR();

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

//void drakmonLogParser::WriteProcTree()
//{
//	for (auto& elem : m_ProcessTree.GetTree())
//	{
//		std::cout << "\"PID\":" << elem.first << ' ' << elem.second << std::endl;
//	}
//}

//void DrakmonLogParser::AnalyzeProcessTree()
//{
//	std::ifstream sortedLogFile = OpenFile<std::ifstream>(m_TempLogPath);
//	if (not sortedLogFile.is_open()) RETERR();
//	
//	m_Analyzer = new YaraAnalyzer();
//	if (m_Analyzer->Initilalize() != 0) RETERR();
//
//	if (m_Analyzer->LoadRules(m_RulesPath.data()) != 0) RETERR();
//
//	m_Analyzer->SetCallback(Callback);
//
//	sortedLogFile.close();
//	Functions::CallbackData userData;
//	m_Analyzer->Scan(m_TempLogPath.c_str(), 0, &userData);
//
//	FormRecord(&userData);
//
//	std::remove(m_TempLogPath.c_str());
//	return;
//}

void DrakmonLogParser::AnalyzeProcessTree()
{
	m_Analyzer = new YaraAnalyzer();
	if (m_Analyzer->Initilalize() != 0) RETERR();

	if (m_Analyzer->LoadRules(m_RulesPath.data()) != 0) RETERR();

	m_Analyzer->SetCallback(Callback);

	const ProcessTree::ProcessMap map = m_ProcessTree.GetTree();
	Functions::CallbackData userData;

	for (const auto& [key, value] : map)
	{
		string jsonString = to_string(value.Get());
		m_Analyzer->Scan((uint8_t*)jsonString.data(), jsonString.length(), 0, &userData);
	}

	FormRecord(&userData);

	std::remove(m_TempLogPath.c_str());
	return;
}

json DrakmonLogParser::Str2Json(string const Logline) const
{
	json json;
	try
	{
		json = json::parse(Logline);
	}
	JSONCATCH();
	return json;
}

int DrakmonLogParser::InsertProcess(json const json, const uint linenum)
{
	try
	{
		string jsonPlugin = GetOptVal<string>(json, "Plugin").value_or("");
		string jsonMethod = GetOptVal<string>(json, "Method").value_or("");

		if (CheckPreInstalled)
			return 1;

		if (jsonPlugin.empty() || jsonMethod.empty())
			return 2;
		FieldsVec ruleFields = m_Ruleset.GetRuleFields(jsonPlugin, jsonMethod);

		ProcessInfo procInfo(json, ruleFields);
		ProcessInfo* parent = m_ProcessTree.GetProcess(procInfo.GetParentPID());
		if (parent == nullptr || false)
			return 3;

		parent->AppendChild(procInfo.GetPID());
		
		//procInfo.SetLineNumber(linenum);
		m_ProcessTree.Insert(linenum, procInfo);
		return 0;
	}
	catch (json::exception& e)
	{
		return 2;
	}
}

void DrakmonLogParser::InsertPreInstProcess(json const json)
{
	try
	{
		PreInstalled process =
		{
			GetOptVal<uint>(json, "PID").value_or(-1),
			GetOptVal<string>(json, "ProcessName").value_or(""),
		};
		m_PreInstProcs.push_back(process);
	}
	catch (json::exception& e)
	{
		return;
	}
}

bool DrakmonLogParser::CheckPreInstalled(PreInstalled proc)
{
	/*for (auto& e : m_PreInstProcs)
	{
		if (e == proc - HUETA)
			return true;
	}*/
	return false;
}

int DrakmonLogParser::FormRecord(Functions::CallbackData* data)
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

int DrakmonLogParser::Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData)
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

void DrakmonLogParser::SetPreinstPath(const std::string path)
{
	m_PreinstPath = path;
}

void DrakmonLogParser::SetLogPath(const std::string path)
{
	m_LogPath = path;
}

void DrakmonLogParser::SetRecordDirPath(const std::string path)
{
	m_RecordDirPath = path;
}

void DrakmonLogParser::SetRulesPath(const std::string path)
{
	m_RulesPath = path;
}

void DrakmonLogParser::SetSaveMatches(const std::string val)
{
	m_SaveMatches = std::stoi(val);
}
