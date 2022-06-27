#pragma once

#include <algorithm>
#include <vector>
#include "cassert"

#include "proto/file_whitelist.pb.h"

#include "../network_message_handler.h"


template<typename I>
struct IsSmartPointerImpl : std::false_type {};

template<typename I>
struct IsSmartPointerImpl<std::shared_ptr<I>> : std::true_type {};

template<typename T>
struct IsSmartPointer : IsSmartPointerImpl<std::decay_t<T>> {};

// repeated field must be a trival value(not a message)
template<typename T>
std::vector<T>
ResolveRepeated(const google::protobuf::RepeatedPtrField<T>& repeatedField)
{
    if (repeatedField.empty()) return {};
    std::vector<T> retVec;
    std::for_each(repeatedField.begin(), repeatedField.end(),
        [&retVec](auto ele)->void {retVec.emplace_back(std::move(ele)); });
    return retVec;
}

// repeated field must be POD type(not a message)
// meanwhile {FieldTy => VecTy} needs to be cast explicitily 
template< typename VecTy, typename FieldTy,
    std::enable_if_t< !std::is_same<VecTy, FieldTy>::value, bool> = true
>
std::vector<VecTy>
ResolveRepeated(const google::protobuf::RepeatedPtrField<FieldTy>& repeatedField)
{
    if (repeatedField.empty())
        return {};
    std::vector<VecTy> retVec;
    std::for_each(repeatedField.begin(), repeatedField.end(),
        [&retVec](auto ele)->void
        {
            auto vecVal = static_cast<VecTy>(ele);
            retVec.emplace_back(std::move(vecVal));
        });
    return retVec;
}

// FIXME: usbinformation has changed format, modify it
template<typename UsbMsgTy,
    std::enable_if_t< 
    std::is_base_of<::google::protobuf::Message, UsbMsgTy>::value, bool> = true
>
std::vector<USB_INFORMATION>
ResolveRepeatedUsbInfomation(const UsbMsgTy& usbMsg)
{
    auto usbMsgDescriptor = usbMsg.GetDescriptor();
    auto fieldDescriptor = usbMsgDescriptor->FindFieldByName("usb_info");
    assert(fieldDescriptor);
    if (fieldDescriptor == nullptr || !fieldDescriptor->is_repeated())
    {
        return {};
    }
    const auto& usbInfoMsgField = usbMsg.usb_info();
    std::vector<USB_INFORMATION> vecUsbInfo;
    std::for_each(usbInfoMsgField.begin(), usbInfoMsgField.end(),
        [&vecUsbInfo](auto usbInfoMsg)
        {
            USB_INFORMATION usbInfo;
            int copySize{ 0 };
            copySize = std::min(sizeof(USB_INFORMATION::Description), usbInfoMsg.description().size());
            std::copy_n(usbInfoMsg.description().data(), copySize, usbInfo.Description);
            copySize = std::min(sizeof(USB_INFORMATION::UniqueId), usbInfoMsg.unique_id().size());
            std::copy_n(usbInfoMsg.unique_id().data(), copySize, usbInfo.UniqueId);
            copySize = std::min(sizeof(USB_INFORMATION::StrDeviceLetter), usbInfoMsg.str_device_letter().size());
            std::copy_n(usbInfoMsg.str_device_letter().data(), copySize, usbInfo.StrDeviceLetter);
            usbInfo.Capacity = usbInfoMsg.capacity();
            usbInfo.Type = usbInfoMsg.type();
            usbInfo.RegistStatus = usbInfoMsg.register_status();
            usbInfo.Purview = static_cast<PUREVIEW>(usbInfoMsg.pure_view());
            usbInfo.DeviceLetter = usbInfoMsg.device_letter();
            vecUsbInfo.emplace_back(usbInfo);
        });
    return vecUsbInfo;
}

template<typename MsgTy, std::enable_if_t<IsSmartPointer<MsgTy>::value, bool> = true>
vector<NET_FILE_INFO>
ResolveRepeatedFileWhitelist(const MsgTy& message)
{
    auto fieldDescriptor = message->GetDescriptor()->FindFieldByName("file_whitelists");
    assert(fieldDescriptor);
    const auto& whitelistsField = message->file_whitelists();
    std::vector<NET_FILE_INFO> vecFileInfo;
    std::for_each(whitelistsField.begin(), whitelistsField.end(),
        [&vecFileInfo](auto filewhitelist)
        {
            NET_FILE_INFO nfi;
            nfi.Name = filewhitelist.filename();
            nfi.Extension = filewhitelist.extension();
            nfi.AbsolutePath = filewhitelist.fullpath();
            nfi.MD5 = filewhitelist.feature_code();
            vecFileInfo.emplace_back(std::move(nfi));
        });
    // todo:
    DEBUG("solved whitelists size " << vecFileInfo.size());
    return vecFileInfo;
}

template <typename UsbMsgTy,
    std::enable_if_t<
    std::is_base_of<::google::protobuf::Message, UsbMsgTy>::value, bool> = true
>
void AddUsbInfomation(UsbMsgTy& usbMsg, const USB_INFORMATION& usbInfo)
{
    auto usbMsgDescriptor = usbMsg.GetDescriptor();
    auto fieldDescriptor = usbMsgDescriptor->FindFieldByName("usb_info");
    assert(fieldDescriptor);
    if (fieldDescriptor == nullptr || !fieldDescriptor->is_repeated())
    {
        return;
    }
    auto usbInfoField = usbMsg.add_usb_info();
    usbInfoField->set_description(usbInfo.Description);
    usbInfoField->set_unique_id(usbInfo.UniqueId);
    usbInfoField->set_str_device_letter(usbInfo.StrDeviceLetter);
    usbInfoField->set_capacity(usbInfo.Capacity);
    usbInfoField->set_type(usbInfo.Type);
    usbInfoField->set_register_status(usbInfo.RegistStatus);
    usbInfoField->set_pure_view(static_cast<uint32_t>(usbInfo.Purview));
    usbInfoField->set_device_letter(usbInfo.DeviceLetter);
}



