#pragma once
#include <sstream>
#include <string>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <thread>
#include "log.h"

#define DEBUG(stream)     \
{                         \
    std::stringstream ss; \
    ss  << "["        \
        << __func__   \
        << "] | "     \
        << "{"        \
        << std::this_thread::get_id() \
        << "} #"  \
        << __LINE__ << " |" << stream; \
        std::cout << ss.str() << std::endl; \
}

#define DEBUG_MSG(msg)    \
{                            \
    std::stringstream ss;    \
    ss  << ">>>>>\n#" \
        << (msg).GetDescriptor()->full_name() \
        << "#\n" \
        << (msg).DebugString() \
        << "<<<<<"; \
    std::cout << ss.str() << std::endl; \
}

#define LOG_DEBUG(...) DEBUG_LOG(LOGGER_2, __VA_ARGS__) 
#define LOG_INFO(...) INFO_LOG(LOGGER_2, __VA_ARGS__) 
#define LOG_WARN(...) WARN_LOG(LOGGER_2, __VA_ARGS__) 
#define LOG_ERROR(...) ERROR_LOG(LOGGER_2, __VA_ARGS__)
