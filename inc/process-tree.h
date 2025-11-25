#pragma once
#include <iostream>
#include <vector>
#include <map>


using string = std::string;
using uint = unsigned int;

struct DroppedFile
{
	string Name;
	string Path;
	bool isStarted;
	uint PID;
};

class Process
{
public:

	typedef std::vector<DroppedFile> DroppedFileArr;
	typedef std::map<string, uint> FoundFlagsMap;
	typedef std::vector<uint> ChildNodes;

public:

	Process() = default;
	~Process() = default;

	Process(uint PPID, const uint LineNum, bool isPreInst, string ProcName, string Path)
		: ParentPID(PPID), LineNumber(LineNum), isPreInstalled(isPreInst),
		ProcessName(ProcName), Path(Path) {};

	uint GetParentPID() const;
	uint GetLineNum() const;
	bool GetIsPreInstalled() const;
	string GetProcName() const;
	string GetProcPath() const;

	void AddDroppedFile(DroppedFile File);
	void SetFlag(string Flagname, uint Count);
	void AppendChild(uint ChildPID);

private:

	uint ParentPID;
	uint LineNumber;
	bool isPreInstalled;
	string ProcessName;
	string Path;

	DroppedFileArr DroppedFiles;
	FoundFlagsMap FoundFlags;

	ChildNodes Childes;
};
std::ostream& operator<<(std::ostream& os, const Process process);

class ProcessTree
{
public:
	
	typedef std::map<uint, Process> ProcessMap;

public:

	void Insert(uint ParentPID, Process NewNode);
	bool Contains(const uint& PID) const;
	Process* GetProcess(uint PID);
	void SetInjectedPID	(uint PID);
	uint GetInjectedPID(uint PID) const;
	bool IsEmpty() const;
	const ProcessMap& GetTree() const;

protected:

	ProcessMap m_Map;
	uint m_InjectPID;

};