#include <iostream>
#include "../inc/drakmonLogParser.h"
#include "../inc/ArgParser.h"

int StartParser(drakmonLogParser* parser)
{
    time_t start, end;

    start = time(nullptr);
    parser->LoadPreInstProcs();
    parser->SortProcesses();

    end = time(nullptr);
    std::cout << "\nProcess tree built, procesess sorted into new file.";
    std::cout << "\nWork time: " << end - start << " seconds!\n" << std::endl;

    start = end;
    parser->AnalyzeProcessTree();

    end = time(nullptr);
    std::cout << "\nProcess tree analysis complete.";
    std::cout << "\nWork time: " << end - start << " seconds!\n" << std::endl;

    return 0;
}

int SetArgs(drakmonLogParser* logParser, ArgParser* argParser)
{
    if (argParser->Contains("-preinstPath"))
        logParser->SetPreinstPath(argParser->Get("-preinstPath"));
    if (argParser->Contains("-logPath"))
        logParser->SetLogPath(argParser->Get("-logPath"));
    if (argParser->Contains("-recordDir"))
        logParser->SetRecordDirPath(argParser->Get("-recordDir"));
    if (argParser->Contains("-rulesPath"))
        logParser->SetRulesPath(argParser->Get("-rulesPath"));

    return 0;
}

void ShowHelp()
{
    std::cout << std::endl;
    std::cout << "\t-h (--help, -help) - Show help" << std::endl;
    std::cout << "\t-preinstPath - path to json file with preinstalled processes (PID, ProcessName, Path)" << std::endl;
    std::cout << "\t-logPath - path to drakmon log" << std::endl;
    std::cout << "\t-recordDir - path to dir where records will be created" << std::endl;
    std::cout << "\t-rulesPath - path to YARA rules file (must end with \\\\ or /)" << std::endl;
    std::cout << "\tCreated by Deniska and BoBaH" << std::endl;

}

int main(int argc, char** argv)
{
    ArgParser* argParser = new ArgParser();
    drakmonLogParser* logParser = new drakmonLogParser();

    for (int i = 0; i < argc; i++)
    {
        string curArg(argv[i]);
        argParser->Insert(curArg);
    }

    if (argParser->IsHelp())
    {
        ShowHelp();
    }
    else
    {
        SetArgs(logParser, argParser);
        StartParser(logParser);
    }

    return 0;
}
