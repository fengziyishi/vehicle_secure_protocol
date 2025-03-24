#pragma once
#include <string>
#include <mutex>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

class Logger {
public:
    // 修改枚举命名，避免宏冲突
    enum class Level { Debug, Info, Warn, Error };

    class LogStream {
    public:
        LogStream(Level level, const char* file, int line)
            : level_(level), file_(file), line_(line) {}

        template<typename T>
        LogStream& operator<<(T const& value) {
            ss_ << value;
            return *this;
        }

        ~LogStream() {
            Logger::get().log_impl(level_, ss_.str(), file_, line_);
        }

    private:
        Level level_;
        const char* file_;
        int line_;
        std::stringstream ss_;
    };

    // 获取单例
    static Logger& get() {
        static Logger instance;
        return instance;
    }

    // 初始化日志系统
    static void init(const std::string& filename = "", Level level = Level::Info);

private:
    Logger() = default;
    void log_impl(Level level, const std::string& message, 
                 const char* file, int line);
    void init_impl(const std::string& filename, Level level);

    std::ofstream log_file_;
    Level log_level_;
    std::mutex mutex_;
};

// 调整日志宏定义
#define LOG_DEBUG Logger::LogStream(Logger::Level::Debug, __FILE__, __LINE__)
#define LOG_INFO  Logger::LogStream(Logger::Level::Info,  __FILE__, __LINE__)
#define LOG_WARN  Logger::LogStream(Logger::Level::Warn,  __FILE__, __LINE__)
#define LOG_ERROR Logger::LogStream(Logger::Level::Error, __FILE__, __LINE__)
