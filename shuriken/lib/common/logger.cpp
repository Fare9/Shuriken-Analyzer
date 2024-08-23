//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file logger.cpp

#include "shuriken/common/logger.h"
#include "logger.hpp"
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "spdlog/fmt/bundled/args.h"
#include "spdlog/spdlog.h"

using namespace shuriken;


Logger::Logger(Logger &&) = default;
Logger &Logger::operator=(Logger &&) = default;
Logger::~Logger() = default;

Logger::Logger() {
    if constexpr (true) {
        sink_ = spdlog::stderr_color_mt("SHURIKEN");
        sink_->set_level(spdlog::level::warn);
        sink_->set_pattern("%v");
        sink_->flush_on(spdlog::level::warn);
    }
}

LEVEL Logger::get_level() {
    auto &instance = Logger::instance();
    spdlog::level::level_enum lvl = instance.sink_->level();
    switch (lvl) {
        default:
        case spdlog::level::level_enum::off:
            return LEVEL::OFF;
        case spdlog::level::level_enum::trace:
            return LEVEL::TRACE;
        case spdlog::level::level_enum::debug:
            return LEVEL::MYDEBUG;
        case spdlog::level::level_enum::info:
            return LEVEL::INFO;
        case spdlog::level::level_enum::warn:
            return LEVEL::WARN;
        case spdlog::level::level_enum::err:
            return LEVEL::ERR;
        case spdlog::level::level_enum::critical:
            return LEVEL::CRITICAL;
    }
    return LEVEL::TRACE;
}

Logger::Logger(const std::string &filepath) {
    sink_ = spdlog::basic_logger_mt("SHURIKEN", filepath, /* truncate */ true);
    sink_->set_level(spdlog::level::warn);
    sink_->set_pattern("%v");
    sink_->flush_on(spdlog::level::warn);
}

Logger &Logger::instance() {
    if (instance_ == nullptr) {
        instance_ = new Logger{};
        std::atexit(destroy);
    }
    return *instance_;
}

void Logger::reset() {
    Logger::destroy();
    Logger::instance();
}

void Logger::destroy() {
    spdlog::details::registry::instance().drop("SHURIKEN");
    delete instance_;
    instance_ = nullptr;
}

Logger &Logger::set_log_path(const std::string &path) {
    if (instance_ == nullptr) {
        instance_ = new Logger{path};
        std::atexit(destroy);
        return *instance_;
    }
    auto &logger = Logger::instance();
    spdlog::details::registry::instance().drop("SHURIKEN");
    logger.sink_ = spdlog::basic_logger_mt("SHURIKEN", path,
                                           /*truncate=*/true);
    logger.sink_->set_pattern("%v");
    logger.sink_->set_level(spdlog::level::warn);
    logger.sink_->flush_on(spdlog::level::warn);
    return logger;
}

void Logger::set_logger(const spdlog::logger &logger) {
    if (logger.name() != "SHURIKEN") {
        return;
    }

    auto &instance = Logger::instance();
    spdlog::details::registry::instance().drop("SHURIKEN");

    instance.sink_ = std::make_shared<spdlog::logger>(logger);
    instance.sink_->set_pattern("%v");
    instance.sink_->set_level(spdlog::level::warn);
    instance.sink_->flush_on(spdlog::level::warn);
}

const char *to_string(LEVEL e) {
    switch (e) {
        case LEVEL::OFF:
            return "OFF";
        case LEVEL::TRACE:
            return "TRACE";
        case LEVEL::MYDEBUG:
            return "DEBUG";
        case LEVEL::INFO:
            return "INFO";
        case LEVEL::ERR:
            return "ERROR";
        case LEVEL::WARN:
            return "WARN";
        case LEVEL::CRITICAL:
            return "CRITICAL";
        default:
            return "UNDEFINED";
    }
    return "UNDEFINED";
}


void Logger::disable() {
    Logger::instance().sink_->set_level(spdlog::level::off);
}

void Logger::enable() {
    Logger::instance().sink_->set_level(spdlog::level::warn);
}

void Logger::set_level(LEVEL level) {
    switch (level) {
        case LEVEL::OFF: {
            Logger::instance().sink_->set_level(spdlog::level::off);
            Logger::instance().sink_->flush_on(spdlog::level::off);
            break;
        }

        case LEVEL::TRACE: {
            Logger::instance().sink_->set_level(spdlog::level::trace);
            Logger::instance().sink_->flush_on(spdlog::level::trace);
            break;
        }

        case LEVEL::MYDEBUG: {
            Logger::instance().sink_->set_level(spdlog::level::debug);
            Logger::instance().sink_->flush_on(spdlog::level::debug);
            break;
        }

        case LEVEL::INFO: {
            Logger::instance().sink_->set_level(spdlog::level::info);
            Logger::instance().sink_->flush_on(spdlog::level::info);
            break;
        }

        default:
        case LEVEL::WARN: {
            Logger::instance().sink_->set_level(spdlog::level::warn);
            Logger::instance().sink_->flush_on(spdlog::level::warn);
            break;
        }

        case LEVEL::ERR: {
            Logger::instance().sink_->set_level(spdlog::level::err);
            Logger::instance().sink_->flush_on(spdlog::level::err);
            break;
        }

        case LEVEL::CRITICAL: {
            Logger::instance().sink_->set_level(spdlog::level::critical);
            Logger::instance().sink_->flush_on(spdlog::level::critical);
            break;
        }
    }
}

// Public interface

void disable() {
    Logger::disable();
}

void enable() {
    Logger::enable();
}

void set_level(LEVEL level) {
    Logger::set_level(level);
}

void set_path(const std::string &path) {
    Logger::set_log_path(path);
}

void set_logger(const spdlog::logger &logger) {
    Logger::set_logger(logger);
}

void reset() {
    Logger::reset();
}

LEVEL get_level() {
    return Logger::get_level();
}


void shuriken::log(shuriken::LEVEL level, const std::string &msg) {
    switch (level) {
        case LEVEL::OFF:
            break;
        case LEVEL::TRACE:
        case LEVEL::MYDEBUG: {
            SHURIKEN_DEBUG("{}", msg);
            break;
        }
        case LEVEL::INFO: {
            SHURIKEN_INFO("{}", msg);
            break;
        }
        case LEVEL::WARN: {
            SHURIKEN_WARN("{}", msg);
            break;
        }
        case LEVEL::CRITICAL:
        case LEVEL::ERR: {
            SHURIKEN_ERR("{}", msg);
            break;
        }
    }
}

void shuriken::log(LEVEL level, const std::string &fmt,
                   const std::vector<std::string> &args) {
    fmt::dynamic_format_arg_store<fmt::format_context> store;
    for (const std::string &arg: args) {
        store.push_back(arg);
    }
    std::string result = fmt::vformat(fmt, store);
    log(level, result);
}