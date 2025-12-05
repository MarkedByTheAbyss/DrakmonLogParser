#include "../inc/cli-config.h"

void SetupCLIOptions(CLI::App& app) {
    app.add_option("--preinstPath", "Path to preinstalled processes JSON")
        ->check(CLI::ExistingFile);
    
    app.add_option("--logPath", "Path to log")
        ->check(CLI::ExistingFile)
        ->required();
                
    app.add_option("--rulesPath", "Path to YARA rules file");
        
    app.add_option("--saveMatches", "Save log lines matching YARA rules");
}

void ValidateArguments(const CLI::App& app) {
    if (!app.count("--logPath")) {
        throw std::runtime_error("Missing required arguments");
    }
}
