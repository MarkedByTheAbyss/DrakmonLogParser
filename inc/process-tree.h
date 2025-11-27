#pragma once
#include <iostream>
#include <vector>
#include <map>

#include "process-info.h"

class ProcessTree
{
public:
	
	typedef std::map<uint, ProcessInfoExt> ProcessMap;

public:

	void Insert(uint ParentPID, ProcessInfoExt NewNode);
	bool Contains(const uint& PID) const;
	ProcessInfoExt* GetProcess(uint PID);
	void SetInjectedPID	(uint PID);
	uint GetInjectedPID(uint PID) const;
	bool IsEmpty() const;
	const ProcessMap& GetTree() const;

protected:

	ProcessMap m_Map;
	uint m_InjectPID;

};