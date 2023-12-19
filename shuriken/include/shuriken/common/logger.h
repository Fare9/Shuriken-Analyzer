//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file logger.h

#ifndef SHURIKENLIB_LOGGER_H
#define SHURIKENLIB_LOGGER_H

#include <iostream>
#include <spdlog/spdlog.h>

namespace shuriken {

    /// @brief Output where to drop the logging from
    /// Shuriken
    enum logger_output_t {
        TO_CONSOLE = 0, /// stdout
        TO_STDERR,      /// stderr
        TO_FILE         /// given file
    };

    void LOG_TO_STDERR();

    void LOG_TO_STDOUT();

    void LOG_TO_FILE();

    /// @brief Method to retrieve a logger object, this object
    /// will be different depending on the type of logging
    /// required.
    /// @return logger shared object
    spdlog::logger* logger();
}

#endif //SHURIKENLIB_LOGGER_H
