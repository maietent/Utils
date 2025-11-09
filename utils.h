#pragma once

/*
this header file contains:
    helper macros,
    a logger;

more to be added as i think
of more stuff to add.
*/

/* useful includes */
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#if __has_include(<format>)
#include <format>
#else
#include <fmt/core.h>
using std::vformat = fmt::vformat;
#endif

/* windows */
#ifdef _WIN32
#include <windows.h>
#endif

/*
helper for easily checking the return value of a function
*/

/* START OF ENSURE */
#define GET_MACRO(_1, _2, _3, _4, NAME, ...) NAME

#define ENSURE_2(expr, should_return)                           \
    do {                                                        \
        if (!(expr)) {                                          \
            if (should_return)                                  \
                return;                                         \
        }                                                       \
    } while (0)

#define ENSURE_3(expr, success_msg, fail_msg)                   \
    do {                                                        \
        if (expr) {                                             \
            std::cout << success_msg << std::endl;              \
        } else {                                                \
            std::cerr << fail_msg << std::endl;                 \
        }                                                       \
    } while (0)

#define ENSURE_4(expr, success_msg, fail_msg, should_return)    \
    do {                                                        \
        if (expr) {                                             \
            std::cout << success_msg << std::endl;              \
        } else {                                                \
            std::cerr << fail_msg << std::endl;                 \
            if (should_return)                                  \
                return;                                         \
        }                                                       \
    } while (0)

#define ENSURE(...)                                             \
    GET_MACRO(__VA_ARGS__, ENSURE_4, ENSURE_3, ENSURE_2)(__VA_ARGS__)
/* END OF ENSURE */

/*
useful logger with tags, colors and file output
*/

/* START OF LOGGER */
namespace Logger {

inline bool log_to_file = false;
inline std::unique_ptr<std::ofstream> log_file;
#ifdef _WIN32
inline bool allocated_console = false;

inline WORD InfoColor
    = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // cyan
inline WORD WarnColor
    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // yellow
inline WORD ErrorColor = FOREGROUND_RED | FOREGROUND_INTENSITY; // red
#else
inline constexpr const char* RESET = "\033[0m";
inline constexpr const char* RED = "\033[31m";
inline constexpr const char* YELLOW = "\033[33m";
inline constexpr const char* CYAN = "\033[36m";
#endif

inline std::string CurrentTime()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    char buf[20];

#ifdef _WIN32
    std::tm tm_struct;
    localtime_s(&tm_struct, &now_time);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_struct);
#else
    std::tm* tm_struct = std::localtime(&now_time);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_struct);
#endif

    return std::string(buf);
}

#ifdef _WIN32
inline void SetConsoleColor(WORD color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
#endif

inline const char* BaseFileName(const char* path)
{
    const char* file = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '/' || *p == '\\')
            file = p + 1;
    }
    return file;
}

template <typename... Args>
void LogInternal(const char* file, const char* function, int line,
    const std::string& level, const std::string& color,
    const std::string& format_str, Args&&... args)
{
    std::string message
        = std::vformat(format_str, std::make_format_args(args...));

#ifdef _WIN32
    WORD colorCode = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    if (level == "INFO")
        colorCode = InfoColor;
    if (level == "WARN")
        colorCode = WarnColor;
    if (level == "ERROR")
        colorCode = ErrorColor;

    if (allocated_console)
        SetConsoleColor(colorCode);

    std::ostream& out = (level == "ERROR") ? std::cerr : std::cout;
    out << "[" << CurrentTime() << "] [" << level << "] ";
    if (allocated_console)
        SetConsoleColor(
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // reset
    out << "(" << file << ":" << line << " " << function << ") " << message
        << "\n";
#else
    std::ostream& out = (level == "ERROR") ? std::cerr : std::cout;
    out << color << "[" << CurrentTime() << "] [" << level << "] " << RESET
        << "(" << file << ":" << line << " " << function << ") " << message
        << "\n";
#endif

    if (log_to_file && log_file && log_file->is_open()) {
        (*log_file) << "[" << CurrentTime() << "] [" << level << "] " << "("
                    << file << ":" << line << " " << function << ") " << message
                    << "\n";
    }
}

inline void init_logging(bool allocate_console = false, bool to_file = false,
    const std::string& file_path = "log.txt")
{
#ifdef _WIN32
    if (allocate_console && !allocated_console) {
        AllocConsole();
        FILE* fDummy;
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        allocated_console = true;
    }
#endif
    log_to_file = to_file;
    if (log_to_file) {
        log_file = std::make_unique<std::ofstream>(file_path, std::ios::app);
        if (!log_file->is_open()) {
            std::cerr << "[ERROR] failed to open log file: " << file_path
                      << std::endl;
            log_to_file = false;
        }
    }
}

} // namespace Logger

#ifdef _WIN32
#define Log(fmt, ...)                                                          \
    Logger::LogInternal(Logger::BaseFileName(__FILE__), __func__, __LINE__,    \
        "INFO", "", fmt, ##__VA_ARGS__)
#define LogWarn(fmt, ...)                                                      \
    Logger::LogInternal(Logger::BaseFileName(__FILE__), __func__, __LINE__,    \
        "WARN", "", fmt, ##__VA_ARGS__)
#define LogError(fmt, ...)                                                     \
    Logger::LogInternal(Logger::BaseFileName(__FILE__), __func__, __LINE__,    \
        "ERROR", "", fmt, ##__VA_ARGS__)
#else
#define Log(fmt, ...)                                                          \
    Logger::LogInternal(Logger::BaseFileName(__FILE__), __func__, __LINE__,    \
        "INFO", Logger::CYAN, fmt, ##__VA_ARGS__)
#define LogWarn(fmt, ...)                                                      \
    Logger::LogInternal(Logger::BaseFileName(__FILE__), __func__, __LINE__,    \
        "WARN", Logger::YELLOW, fmt, ##__VA_ARGS__)
#define LogError(fmt, ...)                                                     \
    Logger::LogInternal(Logger::BaseFileName(__FILE__), __func__, __LINE__,    \
        "ERROR", Logger::RED, fmt, ##__VA_ARGS__)
#endif
/* END OF LOGGER */
