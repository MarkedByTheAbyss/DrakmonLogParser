#pragma once
#include "cli11.hpp"

void SetupCLIOptions(CLI::App& app);
void ValidateArguments(const CLI::App& app);