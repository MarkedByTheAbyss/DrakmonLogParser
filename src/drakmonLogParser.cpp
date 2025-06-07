#include "../inc/drakmonLogParser.h"

void drakmonLogParser::LoadInjectedPID(const json json)
{
	uint injectedPID = GetOptVal<uint>(json, "InjectedPid").value_or(-1);
	m_ProcessTree.SetIntectedPID(injectedPID);

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

void drakmonLogParser::LoadPreInstProcs()
{
	std::ifstream file = OpenFile<std::ifstream>(m_PreinstPath);
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

void drakmonLogParser::SortProcesses()
{
	std::ifstream file = OpenFile<std::ifstream>(m_LogPath);
	if (not file.is_open())
		return;

	std::ofstream sortedLogFile = OpenFile<std::ofstream>("temp.log");
	if (not sortedLogFile.is_open())
		return;

	string line;

	std::getline(file, line);
	LoadInjectedPID(Str2Json(line));

	uint linenum = 1;
	while (not file.eof())
	{
		std::getline(file, line);
		json json = Str2Json(line);
		if (InsertProcess(json, linenum) == 0)
			sortedLogFile << line + '\n';
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
	std::ifstream sortedLogFile = OpenFile<std::ifstream>("temp.log");
	if (not sortedLogFile.is_open())
		return;
	
	m_Analyzer = new YaraAnalyzer();
	if (m_Analyzer->Initilalize() != 0)
		return;

	//if (m_Analyzer->LoadRules("rules/dropper.yara") != 0)
	if (m_Analyzer->LoadRules(m_RulesPath.data()) != 0)
		return;

	m_Analyzer->SetCallback(Callback);

	Functions::CallbackData userData;

	m_Analyzer->Scan("temp.log", 0, &userData);

	for (auto i = m_Matcher.begin(); i != m_Matcher.end(); i++)
	{
		std::cout << "Match at: " << i->first << " count: " << i->second << '\n';
	}

	FormRecord(&userData);
	LogFileMatches();

	sortedLogFile.close();
	std::remove("temp.log");
	return;
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

	std::ofstream file = OpenFile<std::ofstream>(m_RecordDirPath + "record.json");
	if (!file.is_open())
		return 1;

	json resJson;
	for (auto elem : *data)
	{
		json parentJson, childJson = json::array();
		const string& key = elem.first;
		const std::vector<string>& values = elem.second;
		for (const auto& value : values)
		{
			childJson.insert(childJson.end(), value);
		}
		parentJson = { key, childJson };
		resJson.emplace(parentJson);
	}
	file << resJson;

	file.close();
	return 0;
}

int drakmonLogParser::LogFileMatches()
{
	std::ofstream file = OpenFile<std::ofstream>(m_RecordDirPath + "ruleMatches.json");
	if (!file.is_open())
		return 1;

	file << ruleMatches;

	file.close();
	return 0;
}

int drakmonLogParser::Callback(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData)
{
	YR_RULE* actRule = static_cast<YR_RULE*>(messageData);
	if (!actRule)
	{
		return CALLBACK_ERROR;
	}
	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		Functions::CallbackData* callbackData = static_cast<Functions::CallbackData*>(userData);
		YR_STRING* str;
		yr_rule_strings_foreach(actRule, str)
		{
			if (str)
			{
				YR_RULE* curRule = &context->rules->rules_table[str->rule_idx];
				const char* ruleId = curRule->identifier;
				const char* strId = str->identifier;
				uint count = context->matches[str->idx].count;
				
				json ruleString = { { "string", strId }, { "count", count } };

				if (!m_Matcher.empty() && m_Matcher.contains(ruleId))
					m_Matcher.at(ruleId) += count;
				else
					m_Matcher.insert({ ruleId, { count } });
				const char* tag;
				yr_rule_tags_foreach(curRule, tag)
				{
					switch (STRHASH(tag))
					{
					case STRHASH("URL"):
						Functions::GetUrls(context, str, callbackData);
						break;

					case STRHASH("IP"):
						Functions::GetIps(context, str, callbackData);
						break;

					case STRHASH("SaveMatch"):
						ruleString["matches"] = Functions::GetMatchJson(context, str);
						break;

					default:
						break;
					}
				}
				if (ruleMatches.contains(ruleId))
					ruleMatches[ruleId].push_back(ruleString);
				else
					ruleMatches[ruleId] = json::array({ ruleString });
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