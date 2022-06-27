#pragma once

#include "MessageYeildingHelper.hpp"
#include "MyDebug.hpp"

inline std::shared_ptr<google::protobuf::Message>
WrapAsMetadataMessage(const std::shared_ptr<google::protobuf::Message>& msgContentPtr)
{
    if(!msgContentPtr)
    {
        //std::cout << "[log] msgContentPtr null\n";
        LOG_DEBUG("[log] msgContentPtr null");
        return {};
    }
    auto metadata = std::make_shared<bolean::websocket::MetaData>();
    const auto tp = 
        MessageYeildingHelper::YeildCorrespondingTypeFromDescriptorName<bolean::websocket::MsgType>(msgContentPtr->GetDescriptor()->full_name());

    if (tp == bolean::websocket::MsgType::UNKNOWN_MSGTYPE)
    {
        //std::cout << "[warning] The message type has not been registered into the map\n";
        LOG_ERROR("[warning] The message type has not been registered into the map");
        return {};
    }

    metadata->set_message_id(MessageYeildingHelper::GetInstance().GenMsgNo());
    metadata->set_type_info(tp);
    metadata->set_data_content(msgContentPtr->SerializeAsString());
    // todo: set check_sum if needed

    return metadata;
}

