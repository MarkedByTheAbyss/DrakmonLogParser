#include "parser_controller.h"
#include "cli_config.h"
#include <memory>
#include <iostream>

int main(int argc, char** argv) {
    try {
        CLI::App app{"drakmonLogParser - tool for parsing drakmon logs"};
        SetupCLIOptions(app);
        CLI11_PARSE(app, argc, argv);
        
        ValidateArguments(app);
        
        auto parser = std::make_unique<drakmonLogParser>();
        ParserController::Configure(*parser, app);
        return ParserController::Start(parser.get());
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}