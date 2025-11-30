#pragma once
#include "drakmon-log-parser.h"
#include "cli-config.h"
#include <memory>
#include <functional>

class ParserController {
public:
    static void Configure(DrakmonLogParser& parser, const CLI::App& app);
    static int Start(DrakmonLogParser& parser);
    
private:
    static void PrintTimeStats(const std::string& message, time_t& start, time_t& end);
};