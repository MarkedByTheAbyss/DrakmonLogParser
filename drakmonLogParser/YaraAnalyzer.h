#pragma once
#include <iostream>
#include <yara/compiler.h>
#include <yara/libyara.h>
#include <yara/rules.h>


class YaraAnalyzer
{
public:


public:

	YaraAnalyzer() : m_Rules(nullptr) {};
	~YaraAnalyzer();
	int Initilalize();
	void SetCallback(YR_CALLBACK_FUNC func);
	int LoadRules(const char* filename, YR_COMPILER* compiler = nullptr, bool destroy = true);
	int LoadRules(const char** filenamesArray);
	int Scan(const uint8_t* buf, size_t bufSize, int flags, void* userData, int timeout = 0);
	int Scan(const char* filename, int flags, void* userData, int timeout = 0);
	YR_RULES* GetRules() const;

protected:


protected:

	YR_RULES* m_Rules;
	YR_CALLBACK_FUNC m_Callback;

};