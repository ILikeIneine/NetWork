#include "demo_client.h"

using namespace std::chrono_literals;
int main()
{
    custom_client c;
    c.connect("127.0.0.1", 60000);

    bool bQuit = false;
    while (!bQuit)
    {
        /*
        if (GetForegroundWindow() == GetConsoleWindow())
        {
            key[0] = GetAsyncKeyState('A') & 0x8000;
            key[1] = GetAsyncKeyState('B') & 0x8000;
            key[2] = GetAsyncKeyState('C') & 0x8000;
        }

        if (key[0] && !old_key[0]) c.ping_server();
        if (key[1] && !old_key[1]) c.message_all();
        if (key[2] && !old_key[2]) bQuit = true;

        for (int i = 0; i < 3; i++) old_key[i] = key[i];
        */

        c.ping_server();
        std::this_thread::sleep_for(3s);

        if (c.is_connected())
        {
            if (!c.incoming_queue().empty())
            {
                auto msg = c.incoming_queue().pop_front().msg_entity;

                switch (msg.header.id)
                {
                    case CustomMsgTypes::ServerAccept:
                    {
                        // Server has responded to a ping request
                        std::cout << "Server Accepted Connection\n";
                    }
                        break;


                    case CustomMsgTypes::ServerPing:
                    {
                        // Server has responded to a ping request
                        std::chrono::system_clock::time_point timeNow = std::chrono::system_clock::now();
                        std::chrono::system_clock::time_point timeThen;
                        msg >> timeThen;
                        std::cout << "Ping: " << std::chrono::duration<double>(timeNow - timeThen).count() << "\n";
                    }
                        break;

                    case CustomMsgTypes::ServerMessage:
                    {
                        // Server has responded to a ping request
                        constexpr uint32_t clientID{};
                        msg >> clientID;
                        std::cout << "Hello from [" << clientID << "]\n";
                    }
                        break;
                    default:;
                }
            }
        } else
        {
            std::cout << "Server Down\n";
            bQuit = true;
        }
    }

    return 0;
}
