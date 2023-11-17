#pragma once

#include "net.h"
#include "net_client.h"

enum class CustomMsgTypes : uint32_t
{
    ServerAccept, ServerDeny, ServerPing, MessageAll, ServerMessage,
};

class custom_client : public hnk::net::client_interface<CustomMsgTypes>
{
public:
    void ping_server()
    {
        hnk::net::message<CustomMsgTypes> msg;
        msg.header.id = CustomMsgTypes::ServerPing;

        const std::chrono::system_clock::time_point time_now = std::chrono::system_clock::now();
        msg << time_now;
        send(msg);
    }

    void message_all()
    {
        hnk::net::message<CustomMsgTypes> msg;
        msg.header.id = CustomMsgTypes::ServerPing;
        send(msg);
    }
};