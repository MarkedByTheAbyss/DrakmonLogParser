#pragma once
#include <iostream>

#if defined(_WIN32) || defined(_WIN64)
#include <../inc/yara/compiler.h>
#include <../inc/yara/libyara.h>
#include <../inc/yara/rules.h>
#else
#include <yara/compiler.h>
#include <yara/libyara.h>
#include <yara/rules.h>
#endif

#include "../src/functions.cpp"

class YaraAnalyzer
{
public:


public:

	YaraAnalyzer() : m_Rules(nullptr), m_Callback(nullptr) {};
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