#pragma once
#include <iostream>
#include <string>
#include <chrono>
#include <fstream>
#include <cmath>
#include <algorithm>

struct ProfileResult
{
    std::string Name;
    long long Start, End;
};

struct InstrumentationSession
{
    std::string Name;
};

class Instrumentor
{
private:
    InstrumentationSession* m_CurrentSession;
    std::ofstream m_OutputStream;
    int m_ProfileCount;
public:
    Instrumentor()
        : m_CurrentSession(nullptr), m_ProfileCount(0)
    {
    }
    ~Instrumentor() = default;

    void BeginSession(const std::string& name, const std::string& filepath = "result.json")
    {
        m_OutputStream.open(filepath);
        std::cout << "file opened\n";
        WriteHeader();
        m_CurrentSession = new InstrumentationSession{ name };
    }

    void EndSession()
    {
        WriteFooter();
        m_OutputStream.close();
        delete m_CurrentSession;
        m_CurrentSession = nullptr;
        m_ProfileCount = 0;
    }

    void WriteProfile(const ProfileResult& result)
    {
        if (m_ProfileCount++ > 0)
            m_OutputStream << ",";
        std::string name = result.Name;
        std::replace(name.begin(), name.end(), '"', '\'');

        m_OutputStream << "{";
        m_OutputStream << R"("cat":"function",)";
        m_OutputStream << "\"dur\":" << (result.End - result.Start) << ',';
        m_OutputStream << R"("name":")" << name << "\",";
        m_OutputStream << R"("ph":"X",)";
        m_OutputStream << "\"pid\":0,";
        m_OutputStream << "\"tid\":0,";
        m_OutputStream << "\"ts\":" << result.Start;
        m_OutputStream << "}";
        m_OutputStream.flush();
    }

    void WriteHeader()
    {
        m_OutputStream << R"({"otherData": {},"traceEvents":[)";
        m_OutputStream.flush();
    }

    void WriteFooter()
    {
        std::cout << "writeFooter\n";
        m_OutputStream << "]}";
        m_OutputStream.flush();
    }

    static Instrumentor& Get()
    {
        static Instrumentor* instance = new Instrumentor();
        return *instance;
    }

};



class SessionTimer
{
public:
    SessionTimer(const char* name)
        : m_Name(name), m_Stopped(false)
    {
        m_StartTimepoint = std::chrono::steady_clock::now();
    }
    ~SessionTimer()
    {
        if (!m_Stopped)
            Stop();
    }

    void Stop()
    {
        const auto endTimepoint = std::chrono::high_resolution_clock::now();
        const long long start = std::chrono::time_point_cast<std::chrono::milliseconds>(m_StartTimepoint).time_since_epoch().count();
        const long long end = std::chrono::time_point_cast<std::chrono::milliseconds>(endTimepoint).time_since_epoch().count();
        std::cout << m_Name << ": " << (end - start) << "ms\n";
        Instrumentor::Get().WriteProfile({ m_Name, start, end });
        m_Stopped = true;
    }

private:
    const char* m_Name;
    std::chrono::time_point<std::chrono::steady_clock> m_StartTimepoint;
    bool m_Stopped;
};

#define BENCHMARK_PREPARE Instrumentor::Get().BeginSession(__FILE__)
#define BENCHMARK_END Instrumentor::Get().EndSession()
#define BENCHMARK_RECORD(FUNC)  SessionTimer st{##FUNC} 


