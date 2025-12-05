#include "../inc/process-tree.h"


void ProcessTree::Insert(uint ParentPID, ProcessInfo NewNode)
{
	this->m_Map.insert({ ParentPID, NewNode });
}

bool ProcessTree::Contains(const uint& pid) const
{
	return this->m_Map.contains(pid);
}

ProcessInfo* ProcessTree::GetProcess(uint PID)
{
	if (m_Map.find(PID) != m_Map.end())
		return &m_Map.at(PID);
	return nullptr;
}

void ProcessTree::SetInjectedPID(uint PID)
{
	this->m_InjectPID = PID;
}

uint ProcessTree::GetInjectedPID(uint PID) const
{
	return m_InjectPID;
}

bool ProcessTree::IsEmpty() const
{
	return m_Map.empty();
}

const ProcessTree::ProcessMap& ProcessTree::GetTree() const
{
	return m_Map;
}

ProcessTree::ProcessMap::const_iterator ProcessTree::begin() const noexcept
{
	return m_Map.begin();
}

ProcessTree::ProcessMap::const_iterator ProcessTree::end() const noexcept
{
	return m_Map.end();
}