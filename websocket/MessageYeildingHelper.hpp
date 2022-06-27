/* This file is a reflection from c-type Enumeration 
 * of Protobuf to the message's decriptor name 
 * 
 * The implement to construct a concret messages needs
 * these reflections
 *
 * if there's more Enum message type added, just define
 * it at the end of this file
 */

#pragma once

#include "proto/data_type.pb.h"
#include "proto/policy_apply.pb.h"
#include "proto/group_policy.pb.h"
#include "proto/metadata.pb.h"
#include <unordered_map>

// FIXME: refactor handler hook with some error_code gen
class HandlerHook
{
public: 
    uint32_t GenMsgNo()
    {
        return ++MsgNo;
    }
private:
    std::atomic<uint32_t> MsgNo{ static_cast<uint32_t>(std::rand() % 114514) };
};

class MessageYeildingHelper : public HandlerHook
{
public:
    ~MessageYeildingHelper() = default;

    static MessageYeildingHelper& GetInstance()
    {
        static MessageYeildingHelper Instance;
        return Instance;
    }

    static std::shared_ptr<google::protobuf::Message>
        YeildCorrespondingMessage(const std::string& descriptorName)
    {
        google::protobuf::Message* message = nullptr;
        const google::protobuf::Descriptor* descriptor =
            google::protobuf::DescriptorPool::generated_pool()->FindMessageTypeByName(descriptorName);
        if (descriptor)
        {
            const google::protobuf::Message* prototype = google::protobuf::MessageFactory::generated_factory()->GetPrototype(descriptor);
            if (prototype)
            {
                message = prototype->New();
            }
        }
        return std::shared_ptr<google::protobuf::Message>(message);
    }

    template <typename T>
    static std::shared_ptr<google::protobuf::Message>
        YeildCorrespondingMessageFromType(T t)
    {
        const auto& descriptorName = YeildCorrespondingDescriptorName<T>(t);
        return YeildCorrespondingMessage(descriptorName);
    }

#if __cplusplus >= 201703L
    template <typename T>
    static std::string YeildCorrespondingDescriptorName(T t)
    {
        // FIXME: check existance
        auto iter = protoMap_<T>.find(t);
        if(iter == protoMap_<T>.end())
        {
            return "";
        }
        return iter->second;
    }
#else
    template <typename T>
    static std::string YeildCorrespondingDescriptorName(T t);
#endif

#if __cplusplus >= 201703L
    template <typename T>
    static T YeildCorrespondingTypeFromDescriptorName(const std::string& name)
    {
        for(auto& pair : protoMap_<T>)
        {
            if(pair.second == name)
            {
                return pair.first;
            }
        }
        return static_cast<T>(0);
    }

#else
    template <typename T>
    static T YeildCorrespondingTypeFromDescriptorName(const std::string& name);
#endif
private:
    MessageYeildingHelper() = default;

#if __cplusplus >= 201703L
    template<class T>
    static std::unordered_map<T, std::string> protoMap_;
#else
    static std::unordered_map<bolean::websocket::MsgType, std::string> msgTyMap_;
    static std::unordered_map<bolean::websocket::PolicyType, std::string> plcyTyMap_;
    static std::unordered_map<bolean::websocket::GroupPolicyType, std::string> grpPlcyMap_;
#endif

};

#if __cplusplus >= 201703L
//  we do nothing for [unknow type] or [self varify]
//  so there is no need to generate message instance of which by name 
//  just ignore with ""
template<>
std::unordered_map<bolean::websocket::MsgType, std::string>
MessageYeildingHelper::protoMap_<bolean::websocket::MsgType>
{
    { bolean::websocket::MsgType::UNKNOWN_MSGTYPE       , "" },
    { bolean::websocket::MsgType::AUTO_REGISTER_REQUEST , "bolean.websocket.AutoRegisterRequest" },
    { bolean::websocket::MsgType::REGISTER_RESPONSE     , "bolean.websocket.RegisterResponse" },
    { bolean::websocket::MsgType::SELF_VARIFY           , "" },
    { bolean::websocket::MsgType::POLICY_APPLY          , "bolean.websocket.PolicyApply" },
    { bolean::websocket::MsgType::REPLY                 , "bolean.websocket.Reply" }
};

template<>
std::unordered_map<bolean::websocket::PolicyType, std::string>
MessageYeildingHelper::protoMap_<bolean::websocket::PolicyType>
{
    { bolean::websocket::PolicyType::UNKNOWN_POLICY_TYPE, "" },
    { bolean::websocket::PolicyType::USBINFO_PACK        , "bolean.websocket.UsbInfoPack" },
    { bolean::websocket::PolicyType::FILE_WHITELIST_PACK , "bolean.websocket.FileWhitelistPack" },
    { bolean::websocket::PolicyType::GROUP_POLICY        , "bolean.websocket.GroupPolicy" },
    { bolean::websocket::PolicyType::SYS_SETTING         , "bolean.websocket.SysSetting" },
    { bolean::websocket::PolicyType::USB_SETTING         , "bolean.websocket.UsbSetting" },
    { bolean::websocket::PolicyType::HOST_PROTECTION     , "bolean.websocket.HostProtection" },
    { bolean::websocket::PolicyType::REG_PROTECTION      , "bolean.websocket.RegProtection" }
};

template<>
std::unordered_map<bolean::websocket::GroupPolicyType, std::string>
MessageYeildingHelper::protoMap_<bolean::websocket::GroupPolicyType>
{
    { bolean::websocket::GroupPolicyType::UNKNOWN_GROUP_POLICY_TYPE , "" },
    { bolean::websocket::GroupPolicyType::ACCOUNT_POLICY            , "bolean.websocket.AccountPolicy" },
    { bolean::websocket::GroupPolicyType::AUDIT_POLICY              , "bolean.websocket.AuditPolicy" },
    { bolean::websocket::GroupPolicyType::SECURITY_OPTION           , "bolean.websocket.SecurityOption" },
};
#else
std::unordered_map<bolean::websocket::MsgType, std::string>
MessageYeildingHelper::msgTyMap_
{
    { bolean::websocket::MsgType::UNKNOWN_MSGTYPE, "" },
    { bolean::websocket::MsgType::AUTO_REGISTER_REQUEST , "bolean.websocket.AutoRegisterRequest" },
    { bolean::websocket::MsgType::REGISTER_RESPONSE     , "bolean.websocket.RegisterResponse" },
    { bolean::websocket::MsgType::SELF_VARIFY           , "" },
    { bolean::websocket::MsgType::POLICY_APPLY          , "bolean.websocket.PolicyApply" },
    { bolean::websocket::MsgType::REPLY                 , "bolean.websocket.Reply" }
};
std::unordered_map<bolean::websocket::PolicyType, std::string>
MessageYeildingHelper::plcyTyMap_ 
{
    { bolean::websocket::PolicyType::UNKNOWN_POLICY_TYPE, "" },
    { bolean::websocket::PolicyType::USBINFO_PACK        , "bolean.websocket.UsbInfoPack" },
    { bolean::websocket::PolicyType::FILE_WHITELIST_PACK , "bolean.websocket.FileWhitelistPack" },
    { bolean::websocket::PolicyType::GROUP_POLICY        , "bolean.websocket.GroupPolicy" },
    { bolean::websocket::PolicyType::SYS_SETTING         , "bolean.websocket.SysSetting" },
    { bolean::websocket::PolicyType::USB_SETTING         , "bolean.websocket.UsbSetting" },
    { bolean::websocket::PolicyType::HOST_PROTECTION     , "bolean.websocket.HostProtection" },
    { bolean::websocket::PolicyType::REG_PROTECTION      , "bolean.websocket.RegProtection" }
};
std::unordered_map<bolean::websocket::GroupPolicyType, std::string>
MessageYeildingHelper::grpPlcyMap_
{
    { bolean::websocket::GroupPolicyType::UNKNOWN_GROUP_POLICY_TYPE, "" },
    { bolean::websocket::GroupPolicyType::ACCOUNT_POLICY            , "bolean.websocket.AccountPolicy" },
    { bolean::websocket::GroupPolicyType::AUDIT_POLICY              , "bolean.websocket.AuditPolicy" },
    { bolean::websocket::GroupPolicyType::SECURITY_OPTION           , "bolean.websocket.SecurityOption" },
};

// BASE TEMP
template <typename T>
std::string
MessageYeildingHelper::YeildCorrespondingDescriptorName(T t)
{
    return "";
}

template <>
inline std::string
MessageYeildingHelper::YeildCorrespondingDescriptorName<bolean::websocket::MsgType>(const bolean::websocket::MsgType t)
{
    auto iter = msgTyMap_.find(t);
    if (iter == msgTyMap_.end())
    {
        return "";
    }
    return iter->second;
}

template <>
inline std::string
MessageYeildingHelper::YeildCorrespondingDescriptorName<bolean::websocket::PolicyType>(const bolean::websocket::PolicyType t)
{
    const auto iter = plcyTyMap_.find(t);
    if (iter == plcyTyMap_.end())
    {
        return "";
    }
    return iter->second;
}

template <>
inline std::string
MessageYeildingHelper::YeildCorrespondingDescriptorName<bolean::websocket::GroupPolicyType>(const bolean::websocket::GroupPolicyType t)
{
    const auto iter = grpPlcyMap_.find(t);
    if (iter == grpPlcyMap_.end())
    {
        return "";
    }
    return iter->second;
}

// BASE TEMP
template <typename T>
T
MessageYeildingHelper::YeildCorrespondingTypeFromDescriptorName(const std::string& name)
{
    return static_cast<T>(0);
}

template<>
inline bolean::websocket::MsgType
MessageYeildingHelper::YeildCorrespondingTypeFromDescriptorName<bolean::websocket::MsgType>(const std::string& name)
{
    for (auto& pair : msgTyMap_)
    {
        if (pair.second == name)
        {
            return pair.first;
        }
    }
    return static_cast<bolean::websocket::MsgType>(0);
}

template<>
inline bolean::websocket::PolicyType
MessageYeildingHelper::YeildCorrespondingTypeFromDescriptorName<bolean::websocket::PolicyType>(const std::string& name)
{
    for (auto& pair : plcyTyMap_)
    {
        if (pair.second == name)
        {
            return pair.first;
        }
    }
    return static_cast<bolean::websocket::PolicyType>(0);
}

template<>
inline bolean::websocket::GroupPolicyType
MessageYeildingHelper::YeildCorrespondingTypeFromDescriptorName<bolean::websocket::GroupPolicyType>(const std::string& name)
{
    for (auto& pair : grpPlcyMap_)
    {
        if (pair.second == name)
        {
            return pair.first;
        }
    }
    return static_cast<bolean::websocket::GroupPolicyType>(0);
}
#endif


