//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file logger.cpp

#include "shuriken/common/logger.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

using namespace shuriken;

/// @brief global variable, set to the proper value
shuriken::logger_output_t global_logger_output = shuriken::logger_output_t::TO_STDERR;

std::string log_filename = "";

void shuriken::LOG_TO_STDERR()
{
    global_logger_output = shuriken::logger_output_t::TO_STDERR;
}

void shuriken::LOG_TO_STDOUT()
{
    global_logger_output = shuriken::logger_output_t::TO_CONSOLE;
}

void shuriken::LOG_TO_FILE()
{
    global_logger_output = shuriken::logger_output_t::TO_FILE;
}

spdlog::logger* shuriken::logger() {
    static std::shared_ptr<spdlog::logger> logger;

    if (logger != nullptr)
        return logger.get();

    switch (global_logger_output)
    {
        case shuriken::logger_output_t::TO_CONSOLE:
            logger = spdlog::get("console");
            if (logger == nullptr)
                logger = spdlog::stdout_color_mt("console");
            break;
        case shuriken::logger_output_t::TO_STDERR:
            logger = spdlog::get("stderr");
            if (logger == nullptr)
                logger = spdlog::stderr_color_mt("stderr");
            break;
        case shuriken::logger_output_t::TO_FILE:
            logger = spdlog::get("file_logger");
            if (logger == nullptr)
            {
                if (log_filename.empty())
                    throw std::runtime_error("logger(): log_file_name "
                                                        "provided is empty");
                logger = spdlog::basic_logger_mt("file_logger", log_filename);
            }
        default:
            throw std::runtime_error("logger(): Option provided for "
                                                "'global_logger_output' not valid");
    }

    return logger.get();
}