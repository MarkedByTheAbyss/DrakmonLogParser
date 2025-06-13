#include "../inc/YaraAnalyzer.h"
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0L
#endif

YaraAnalyzer::~YaraAnalyzer()
{
	if (m_Rules)
		yr_rules_destroy(m_Rules);
	yr_finalize();
}

int YaraAnalyzer::Initilalize()
{
	if (yr_initialize() != ERROR_SUCCESS)
	{
		LOGERR();
		return 1;
	}
	return 0;
	YR_CONFIG_MAX_MATCH_DATA;
}
void YaraAnalyzer::SetCallback(YR_CALLBACK_FUNC func)
{
	m_Callback = func;
}

int YaraAnalyzer::LoadRules(const char* filename, YR_COMPILER* compiler, bool destroy)
{
	FILE* file;

#if defined(_WIN32) || defined (_WIN64)
	fopen_s(&file, filename, "r");
#else
	file = fopen(filename, "r");
#endif 

	if (!file)
	{
		LOGERR();
		return 1;
	}

	if (compiler == nullptr)
	{
		if (yr_compiler_create(&compiler) != ERROR_SUCCESS) 
		{
			LOGERR();
			return 2;
		}
	}

	int errorCount = yr_compiler_add_file(compiler, file, nullptr, filename);
	if (errorCount > 0)
	{
		LOGERR();
		if (destroy)
			yr_compiler_destroy(compiler);
		return 3;
	}

	if (yr_compiler_get_rules(compiler, &m_Rules) != ERROR_SUCCESS)
	{
		LOGERR();
		if (destroy)
			yr_compiler_destroy(compiler);
		return 4;
	}

	if (destroy)
		yr_compiler_destroy(compiler);

	fclose(file);
	return 0;	
}

int YaraAnalyzer::Scan(const uint8_t* buf, size_t bufSize, int flags, void* userData, int timeout)
{
	int result = yr_rules_scan_mem(
		m_Rules,
		buf,
		bufSize,
		flags,
		m_Callback,
		userData,
		timeout);

	if (result > 0)
		return 1;
	return 0;
}

int YaraAnalyzer::Scan(const char* filename, int flags, void* userData, int timeout)
{
	int len = 1024;
	yr_set_configuration_uint32(YR_CONFIG_MAX_MATCH_DATA, len);

	int result = yr_rules_scan_file(
		m_Rules,
		filename,
		flags,
		m_Callback,
		userData,
		timeout);

	if (result > 0)
		return 1;
	return 0;
}

YR_RULES* YaraAnalyzer::GetRules() const
{
	return m_Rules;
}

