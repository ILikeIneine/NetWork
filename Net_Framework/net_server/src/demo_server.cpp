#include "demo_server.h"

int main()
{
    custom_server svr(60000);
    svr.start();

    while (true)
    {
        svr.update(-1, true);
    }
}
