#include "utils/logger.h"
#include <iostream>

void Logger::init_impl(const std::string& filename, Level level) {
    log_level_ = level;
    if (!filename.empty()) {
        log_file_.open(filename, std::ios::app);
    }
}

void Logger::log_impl(Level level, const std::string& message, 
                     const char* file, int line) {
    if (level < log_level_) return;

    auto now = std::chrono::system_clock::now();
    auto now_time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&now_time);

    std::string level_str;
    switch (level) {
        case Level::Debug: level_str = "DEBUG"; break;
        case Level::Info:  level_str = "INFO";  break;
        case Level::Warn:  level_str = "WARN";  break;
        case Level::Error: level_str = "ERROR"; break;
    }

    std::stringstream prefix;
    prefix << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
           << "[" << level_str << "] "
           << file << ":" << line << " - ";

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << prefix.str() << message << std::endl;
    if (log_file_.is_open()) {
        log_file_ << prefix.str() << message << std::endl;
    }
}
