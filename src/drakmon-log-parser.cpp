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
	m_ProcessPipeline.Load("e:\\GitRepos\\drakmonLogParser\\DrakmonLogParser\\parsing_rules\\rules.json");

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

	if (m_Analyzer->Load(m_RulesPath.c_str()) != 0) RETERR();

	m_Analyzer->SetCallback(Callback);

	const ProcessTree::ProcessMap map = m_ProcessTree.GetTree();
	Functions::CallbackInfo callbackInfo;
	json recordData = json::array();

	for (const auto& [key, value] : map)
	{
		string jsonString = to_string(value.Get());
		m_Analyzer->Scan((uint8_t*)jsonString.data(), jsonString.length(), 0, &callbackInfo);
		AddRecordData(recordData, callbackInfo);
		callbackInfo.clear();
	}

	FormRecord(recordData);
	SaveDebugInfo();

	std::remove(m_TempLogPath.c_str());
	return;
}

void DrakmonLogParser::AddRecordData(json& jsonData, const Functions::CallbackInfo& info)
{
	if (info.matchInfo.rule == nullptr)
		return;

	string rule = info.matchInfo.rule;
	string str = info.matchInfo.string;

	bool isRuleFound = false;
	for (json& ruleJson : jsonData)
	{
		if (ruleJson["Rule"] == rule)
		{
			isRuleFound = true;
			ruleJson["Count"] = ruleJson["Count"] + 1; 
			if (not info.parsedInfo.empty())
				ruleJson["AdditionalInfo"].push_back(info.parsedInfo);

			bool isStringFound = false;
			for (json& strJson : ruleJson["Strings"])
			{
				if (strJson["String"] == str)
				{
					isStringFound = true;
					strJson["Count"] = strJson["Count"] + 1;

					break;
				}
			}
			if (not isStringFound)
			{
				json strJson;
				strJson["String"] = str;
				strJson["Count"] = 1;
				ruleJson["Strings"].push_back(strJson);
			}

			break;
		}
	}
	if (not isRuleFound)
	{
		json ruleJson;
		ruleJson["Rule"] = rule;
		ruleJson["Count"] = 1;
		ruleJson["Strings"] = json::array();
		ruleJson["AdditionalInfo"] = json::array();

		if (not info.parsedInfo.empty())
			ruleJson["AdditionalInfo"].push_back(info.parsedInfo);

		json strJson;
		strJson["String"] = str;
		strJson["Count"] = 1;
		ruleJson["Strings"].push_back(strJson);

		jsonData.push_back(ruleJson);
	}
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

		//if (CheckPreInstalled)
			//return 1;

		if (jsonPlugin.empty() || jsonMethod.empty())
			return 2;
		JsonFieldsVector ruleFields = m_ProcessPipeline.GetExtractionRuleFields(jsonPlugin, jsonMethod);

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

int DrakmonLogParser::FormRecord(const json& recordJson)
{
	if (not recordJson.is_array())
		return 1;

	std::ofstream recordFile = OpenFile<std::ofstream>(m_RecordDirPath + "record.json");
	if (!recordFile.is_open())
	{
		LOGERR();
		return 2;
	}

	recordFile << recordJson.dump(4);
	
	recordFile.close();
	return 0;
}

int DrakmonLogParser::Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData)
{
	YR_RULE* actRule = static_cast<YR_RULE*>(messageData);
	if (actRule && message == CALLBACK_MSG_RULE_MATCHING)
	{
		Functions::CallbackInfo* callbackData = static_cast<Functions::CallbackInfo*>(userData);
		YR_STRING* str;
		yr_rule_strings_foreach(actRule, str)
		{
			if (str)
			{
				Functions::SetMatchesInfo(callbackData, actRule->identifier, str->identifier);

				json ruleStringsExt;
				const char* tag;
				yr_rule_tags_foreach(actRule, tag)
				{
					switch (STRHASH(tag))
					{
					case STRHASH("URL"):
						ruleStringsExt["URL"] = Functions::GetUrls(context, str);
						break;

					case STRHASH("IP"):
						ruleStringsExt["IP"] = Functions::GetIps(context, str);
						break;

					default:
						break;
					}
				}
				if (!ruleStringsExt.empty())
					Functions::AddRuleData(callbackData, actRule->identifier, ruleStringsExt);
			}
		}
	}
	return CALLBACK_CONTINUE;
}

void DrakmonLogParser::SetRecordDirPath()
{
	using namespace std::chrono;

	std::stringstream ss;
	ss << "debug\\";
	
	auto now = time_point_cast<milliseconds>(system_clock::now());
	ss << std::format("{:%d-%m-%Y %H.%M.%S}", now) << ' ';

	ss << '[' << m_LogPath.substr(m_LogPath.rfind("\\") + 1) << ']' << '\\';
	m_RecordDirPath = ss.str();

	if (!std::filesystem::is_directory(m_RecordDirPath))
		std::filesystem::create_directories(m_RecordDirPath);
}

void DrakmonLogParser::SetPreinstPath(const std::string path)
{
	m_PreinstPath = path;
}

void DrakmonLogParser::SetLogPath(const std::string path)
{
	m_LogPath = path;
}

void DrakmonLogParser::SetRulesPath(const std::string path)
{
	m_RulesPath = path;
}

void DrakmonLogParser::SetSaveMatches(const std::string val)
{
	m_SaveMatches = std::stoi(val);
}

void DrakmonLogParser::SaveDebugInfo() 
{
	std::ofstream debugFile = OpenFile<std::ofstream>(m_RecordDirPath + "debug.json");
	if (!debugFile.is_open())
	{
		LOGERR();
		return;
	}
	debugFile << "[\n";
	bool first = true;
	for (auto& [key, value] : m_ProcessTree)
	{
		if (!first)
			debugFile << ",\n";
		debugFile << value.Get().dump(4);
		first = false;
	}
	debugFile << "]\n";

	debugFile.close();
}