#pragma once
#include <iostream>
#include <vector>
#include <map>

#include "process-info.h"

class ProcessTree
{
public:
	
	typedef std::map<uint, ProcessInfo> ProcessMap;

public:

	void Insert(uint parentPID, ProcessInfo newNode);
	bool Contains(const uint& pid) const;
	ProcessInfo* GetProcess(uint pid);
	void SetInjectedPID	(uint pid);
	uint GetInjectedPID(uint pid) const;
	bool IsEmpty() const;
	const ProcessMap& GetTree() const;

protected:

	ProcessMap m_Map;
	uint m_InjectPID;

};