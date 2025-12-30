#include "../inc/ruleset.h"


int ProcessPipeline::Load(string filename)
{
	int status = 0;
	try
	{
		std::ifstream file(filename);
		json rulesetJson;
		file >> rulesetJson;

		for (const json& e : rulesetJson)
		{
			Insert(e);
		}
	}
	catch (json::exception e)
	{
		std::cout << e.what();
		status = 1;
	}
	return status;
}

void ProcessPipeline::Insert(const json& rule)
{
	string pluginName = GetOptVal<string>(rule, "Plugin").value_or("");
	json methods = GetOptVal<json>(rule, "Methods").value_or(NULL);
	json pluginFields = GetOptVal<json>(rule, "Fields").value_or(NULL);

	if (pluginName.empty() || methods == NULL)
		return;

	uint pluginHash = STRHASH(pluginName.c_str());
	if (methods != NULL)
	{
		for (const json& methodJson : methods)
		{
			json methodFields;
			string methodName = GetOptVal<string>(methodJson, "Method").value_or("");

			if (methodJson.contains("Fields"))
				methodFields = GetOptVal<json>(methodJson, "Fields").value_or(NULL);

			uint methodHash = STRHASH(methodName.c_str());
			m_ExtractionRuleset[pluginHash].insert({ methodHash, {} });

			if (pluginFields != NULL);
				for (const string& field : pluginFields)
					m_ExtractionRuleset[pluginHash][methodHash].push_back(field);

			if (methodFields != NULL)
				for (const string& field : methodFields)
					m_ExtractionRuleset[pluginHash][methodHash].push_back(field);


			string methodRegexString = GetOptVal<string>(methodJson, "Regex").value_or("");
			if (not methodRegexString.empty())
			{
				regex methodRegex(methodRegexString);
				m_ParsingRuleset[pluginHash][methodHash] = methodRegex;
			}
		}
	}
	
}

JsonFieldsVector ProcessPipeline::GetExtractionRuleFields(string plugin, string method) const
{
	uint pluginHash = STRHASH(plugin.c_str());
	uint methodHash = STRHASH(method.c_str());
	JsonFieldsVector retVal;

	if (m_ExtractionRuleset.contains(pluginHash))
		if (m_ExtractionRuleset.at(pluginHash).contains(methodHash))
			retVal = m_ExtractionRuleset.at(pluginHash).at(methodHash);

	return retVal;
}

regex ProcessPipeline::GetParsingRuleRegex(string plugin, string method) const
{
	uint pluginHash = STRHASH(plugin.c_str());
	uint methodHash = STRHASH(method.c_str());
	regex retVal;

	if (m_ParsingRuleset.contains(pluginHash))
		if (m_ParsingRuleset.at(pluginHash).contains(methodHash))
			retVal = m_ParsingRuleset.at(pluginHash).at(methodHash);

	return retVal;
}
