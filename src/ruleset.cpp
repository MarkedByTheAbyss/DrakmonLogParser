#include "../inc/ruleset.h"


int Ruleset::LoadRules(string filename)
{
	int status = 0;
	try
	{
		std::ifstream file(filename);
		json rulesetJson;
		file >> rulesetJson;

		for (const json& e : rulesetJson)
		{
			InsertRule(e);
		}
	}
	catch (json::exception e)
	{
		std::cout << e.what();
		status = 1;
	}
	return status;
}

void Ruleset::InsertRule(const json& rule)
{
	string pluginName = GetOptVal<string>(rule, "Plugin").value_or("");
	json methods = GetOptVal<json>(rule, "Methods").value_or(NULL);
	json pluginFields = GetOptVal<json>(rule, "Fields").value_or(NULL);

	if (pluginName.empty() || methods == NULL)
		return;

	uint pluginHash = STRHASH(pluginName.c_str());
	if (methods != NULL)
	{
		//if (not m_RulesetMap.contains(pluginHash))
		//	m_RulesetMap.insert({ pluginHash, {} });

		for (const json& methodJson : methods)
		{
			string methodName = GetOptVal<string>(methodJson, "Method").value_or("");
			json methodFields;
			if (methodJson.contains("Fields"))
				methodFields = GetOptVal<json>(methodJson, "Fields").value_or(NULL);

			uint methodHash = STRHASH(methodName.c_str());
			m_RulesetMap[pluginHash].insert({ methodHash, {} });


			if (pluginFields != NULL);
				for (const string& field : pluginFields)
					m_RulesetMap[pluginHash][methodHash].push_back(field);

			if (methodFields != NULL)
				for (const string& field : methodFields)
					m_RulesetMap[pluginHash][methodHash].push_back(field);
		}
	}
	
}

std::vector<string> Ruleset::GetRuleFields(string plugin, string method) const
{
	uint pluginHash = STRHASH(plugin.c_str());
	uint methodHash = STRHASH(method.c_str());
	std::vector<string> retVal;

	if (m_RulesetMap.contains(pluginHash))
		if (m_RulesetMap.at(pluginHash).contains(methodHash))
			retVal = m_RulesetMap.at(pluginHash).at(methodHash);

	return retVal;
}
