#pragma once
#include "drakmonLogParser.h"
#include "cli_config.h"
#include <memory>
#include <functional>

class ParserController {
public:
    static void Configure(drakmonLogParser& parser, const CLI::App& app);
    static int Start(drakmonLogParser* parser);
    
private:
    static void PrintTimeStats(const std::string& message, time_t start, time_t end);
};