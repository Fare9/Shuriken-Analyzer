//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file logger.h
// @brief Logger taken from Lief project, we avoid exposing spdlog out of the
// library

#ifndef SHURIKENLIB_LOGGER_H
#define SHURIKENLIB_LOGGER_H

#include <iostream>
#include <vector>

namespace spdlog {
    class logger;
}

namespace shuriken {

    /// @brief Output where to drop the logging from
    /// Shuriken
    enum class LEVEL : uint32_t {
        OFF = 0,

        TRACE,
        MYDEBUG,
        INFO,
        WARN,
        ERR,
        CRITICAL,
    };

    LEVEL get_level();

    const char * to_string(LEVEL e);

    void disable();

    //! Globally enable the logging module
    void enable();

    //! Change the logging level (**hierarchical**)
    void set_level(LEVEL level);

    //! Change the logger as a file-base logging and set its path
    void set_path(const std::string& path);

    //! Log a message with the LIEF's logger
    void log(LEVEL level, const std::string& msg);

    void log(LEVEL level, const std::string& fmt,
                      const std::vector<std::string>& args);

    template <typename... Args>
    void log(LEVEL level, const std::string& fmt, const Args &... args) {
        std::vector<std::string> vec_args;
        vec_args.insert(vec_args.end(), { static_cast<decltype(vec_args)::value_type>(args)...});
        return log(level, fmt, vec_args);
    }

    void set_logger(const spdlog::logger& logger);

    void reset();

    class Scoped {
    public:
        Scoped(const Scoped&) = delete;
        Scoped& operator=(const Scoped&) = delete;

        Scoped(Scoped&&) = delete;
        Scoped& operator=(Scoped&&) = delete;

        explicit Scoped(LEVEL level) :
                                       level_(get_level())
        {
            set_level(level);
        }

        const Scoped& set_level(LEVEL lvl) const {
            shuriken::set_level(lvl);
            return *this;
        }

        ~Scoped() {
            set_level(level_);
        }

    private:
        LEVEL level_ = LEVEL::INFO;
    };
}// namespace shuriken

#endif//SHURIKENLIB_LOGGER_H
