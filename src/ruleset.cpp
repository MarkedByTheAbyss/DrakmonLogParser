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
		status = 1;
	}
	return status;
}

void Ruleset::InsertRule(const json& rule)
{
	string plugin = GetOptVal<string>(rule, "Plugin").value_or("");
	string method = GetOptVal<string>(rule, "Method").value_or("");
	json fields = GetOptVal<json>(rule, "Fields").value_or(NULL);

	uint pluginHash;
	uint methodHash;
	if (not plugin.empty())
		pluginHash = STRHASH(plugin.c_str());
	if (not method.empty())
		methodHash = STRHASH(method.c_str());
	if (fields != NULL)
		if (not m_RulesetMap.contains(pluginHash))
			m_RulesetMap.insert({ pluginHash, {} });
		m_RulesetMap[pluginHash].insert({ methodHash, fields });
}

json Ruleset::GetRule(string plugin, string method) const
{
	uint pluginHash = STRHASH(plugin.c_str());
	uint methodHash = STRHASH(method.c_str());
	json retVal = NULL;

	if (m_RulesetMap.contains(pluginHash))
		if (m_RulesetMap.at(pluginHash).contains(methodHash))
			retVal = m_RulesetMap.at(pluginHash).at(methodHash);

	return retVal;
}
