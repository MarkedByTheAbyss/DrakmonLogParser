#pragma once
#include "CLI11.hpp"

void SetupCLIOptions(CLI::App& app);
void ValidateArguments(const CLI::App& app);