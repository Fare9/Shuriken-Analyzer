//
// Created by fare9 on 21/08/24.
//

#ifndef SHURIKENPROJECT_LOGGER_HPP
#define SHURIKENPROJECT_LOGGER_HPP

#include <memory>
#include "shuriken/common/logger.h"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

#define SHURIKEN_TRACE(...) shuriken::Logger::trace(__VA_ARGS__)
#define SHURIKEN_DEBUG(...) shuriken::Logger::debug(__VA_ARGS__)
#define SHURIKEN_INFO(...)  shuriken::Logger::info(__VA_ARGS__)
#define SHURIKEN_WARN(...)  shuriken::Logger::warn(__VA_ARGS__)
#define SHURIKEN_ERR(...)   shuriken::Logger::err(__VA_ARGS__)

#define CHECK(X, ...)        \
  do {                       \
    if (!(X)) {              \
      SHURIKEN_ERR(__VA_ARGS__); \
    }                        \
  } while (false)


#define CHECK_FATAL(X, ...)  \
  do {                       \
    if ((X)) {               \
      SHURIKEN_ERR(__VA_ARGS__); \
      std::abort();          \
    }                        \
  } while (false)

namespace shuriken {
    class Logger {
    public:
        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        static Logger& instance();

        //! @brief Disable the logging module
        static void disable();

        //! @brief Enable the logging module
        static void enable();

        //! @brief Change the logging level (**hierarchical**)
        static void set_level(LEVEL level);

        static LEVEL get_level();

        static Logger& set_log_path(const std::string& path);

        static void reset();

        template <typename... Args>
        static void trace(const char *fmt, const Args &... args) {
            Logger::instance().sink_->trace(fmt::runtime(fmt), args...);
        }

        template <typename... Args>
        static void debug(const char *fmt, const Args &... args) {
            Logger::instance().sink_->debug(fmt::runtime(fmt), args...);
        }

        template <typename... Args>
        static void info(const char *fmt, const Args &... args) {
            Logger::instance().sink_->info(fmt::runtime(fmt), args...);
        }

        template <typename... Args>
        static void err(const char *fmt, const Args &... args) {
            Logger::instance().sink_->error(fmt::runtime(fmt), args...);
        }

        template <typename... Args>
        static void warn(const char *fmt, const Args &... args) {
            Logger::instance().sink_->warn(fmt::runtime(fmt), args...);
        }

        static void set_logger(const spdlog::logger& logger);

        ~Logger();
    private:
        Logger();
        Logger(const std::string& filepath);
        Logger(Logger&&);
        Logger& operator=(Logger&&);

        static void destroy();
        static inline Logger* instance_ = nullptr;
        std::shared_ptr<spdlog::logger> sink_;
    };
}

#endif//SHURIKENPROJECT_LOGGER_HPP
