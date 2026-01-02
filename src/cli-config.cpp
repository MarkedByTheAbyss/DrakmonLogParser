#include "../inc/cli-config.h"

void SetupCLIOptions(CLI::App& app) {
    app.add_option("--logPath", "Path to log")
        ->check(CLI::ExistingFile)
        ->required();

    app.add_option("--rulesPath", "Path to parsing rules file")
        ->check(CLI::ExistingFile)
        ->required();
                
    app.add_option("--yaraPath", "Path to YARA rules file")
        ->check(CLI::ExistingFile)
        ->required();
        
    app.add_option("--saveMatches", "Save log lines matching YARA rules");

    app.add_option("--preinstPath", "Path to preinstalled processes JSON")
        ->check(CLI::ExistingFile);
}

void ValidateArguments(const CLI::App& app) {
    if (!app.count("--logPath") || !app.count("--rulesPath") 
        || !app.count("--yaraPath")) {
        throw std::runtime_error("Missing required arguments");
    }
}
