#include "ProcessTree.h"

uint Process::GetParentPID() const
{
	return this->ParentPID;
}

uint Process::GetLineNum() const
{
	return this->LineNumber;
}

bool Process::GetIsPreInstalled() const
{
	return this->isPreInstalled;
}

string Process::GetProcName() const
{
	return this->ProcessName;
}

string Process::GetProcPath() const
{
	return this->Path;
}

void Process::AddDroppedFile(DroppedFile File)
{
	this->DroppedFiles.push_back(File);
}

void Process::SetFlag(string Flagname, uint Count)
{
	this->FoundFlags.insert({ Flagname, Count });
}

void Process::AppendChild(uint ChildPID)
{
	this->Childes.push_back(ChildPID);
}

void ProcessTree::Insert(uint ParentPID, Process NewNode)
{
	this->m_Map.insert({ ParentPID, NewNode });
}

Process* ProcessTree::GetProcess(uint PID)
{
	if (m_Map.find(PID) != m_Map.end())
		return &m_Map.at(PID);
	return nullptr;
}

void ProcessTree::SetIntectedPID(uint PID)
{
	this->m_InjectPID = PID;
}

uint ProcessTree::GetIntectedPID(uint PID) const
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

std::ostream& operator<<(std::ostream& os, const Process process)
{
	os << "\"PPID\":" << process.GetParentPID() << ' '
		<< "\"ProcessName\":" << process.GetProcPath() 
		<< process.GetProcName() << ' '
		<< "\"IsPreInstalled\":" << process.GetIsPreInstalled() << ' '
		<< "\"LogLine\":" << process.GetLineNum();
	return os;
}
