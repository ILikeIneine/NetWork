#pragma once
#include "RegistryActions.hpp"

inline
void
RegTest()
{
    const auto vec = registry::GetInstalledAppList64();
    for (auto& app : vec)
    {
        DEBUG(app);
    }
}
