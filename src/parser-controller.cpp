#include "../inc/parser-controller.h"
#include <iostream>

void ParserController::Configure(DrakmonLogParser& parser, const CLI::App& app) {
    auto getOpt = [&app](const char* name) {
        return app.count(name) ? app.get_option(name)->as<std::string>() : "";
    };
    
    const std::pair<const char*, std::function<void(const std::string&)>> options[] = {
        {"--preinstPath", [&parser](const auto& val) { parser.SetPreinstPath(val); }},
        {"--logPath", [&parser](const auto& val) { parser.SetLogPath(val); }},
        {"--rulesPath", [&parser](const auto& val) { parser.SetRulesPath(val); }},
        {"--saveMatches", [&parser](const auto& val) { parser.SetSaveMatches(val); }}
    };
    
    for (const auto& [name, setter] : options) {
        if (auto val = getOpt(name); !val.empty()) {
            setter(val);
        }
    }
}

void ParserController::PrintTimeStats(const std::string& message, time_t& start, time_t& end) {
    std::cout << "\n" << message;
    std::cout << "\nWork time: " << end - start << " seconds!\n" << std::endl;
}

int ParserController::Start(DrakmonLogParser& parser) {
    
    time_t start = time(nullptr);
    parser.SetRecordDirPath();
    parser.LoadPreInstProcs();
    parser.BuildProcessTree();
    time_t end = time(nullptr);
    PrintTimeStats("Process tree built, processes sorted into new file.", start, end);

    start = end;
    parser.AnalyzeProcessTree();
    end = time(nullptr);
    PrintTimeStats("Process tree analysis complete.", start, end);

    return 0;
}