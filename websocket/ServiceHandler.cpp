#include "ServiceHandler.hpp"
#include "MessageYeildingHelper.hpp"
#include "WrapHelper.hpp"
#include "ResolveHelper.hpp"
#include "Sysinfo.hpp"
#include "MyDebug.hpp"

#include "proto/metadata.pb.h"
#include "proto/reply.pb.h"
#include "proto/auto_register_request.pb.h"
#include "proto/register_response.pb.h"
#include "proto/file_whitelist.pb.h"
#include "proto/group_policy.pb.h"
#include "proto/sys_setting.pb.h"
#include "proto/usb_setting.pb.h"
#include "proto/host_protection.pb.h"
#include "proto/reg_protection.pb.h"

ServiceHandler::ServiceHandler()
    : authenticated_(IsAuthorized())
{
    dispatcher_ = std::make_shared<ProtobufDispatcher>(
        [&](const MessagePtr&)-> MessagePtr
        {
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(-1);
            return reply;
        });

    RegisterHandler();
}

ServiceHandler::~ServiceHandler()
{
    if (workThread_.joinable())
    {
        workThread_.join();
    }
    if (replyThread_.joinable())
    {
        replyThread_.join();
    }
    LOG_DEBUG("bye bye meow.");
}

[[noreturn]] void
ServiceHandler::Run()
{
    // producer
    workThread_ = std::thread(&ServiceHandler::OnProcess, shared_from_this());
    // comsumer
    replyThread_ = std::thread(&ServiceHandler::OnRePly, shared_from_this());
    // upload
    std::thread(&ServiceHandler::OnUploads, shared_from_this()).detach();
}


// only for the dispatching, blockable
MessageVec
ServiceHandler::SeizeSomeRecvMessage()
{
    // Thread would block
    std::unique_lock<std::mutex> lk_msg_vec{mutexOfReceiving_};
    //DEBUG("[info] msgReceiving size: [" << msgReceiving_.size() << "]");
    cvRecv_.wait(lk_msg_vec, [&] { return !msgReceiving_.empty(); });
    MessageVec retVec{msgReceiving_.begin(), msgReceiving_.end()};
    msgReceiving_.clear();
    //DEBUG("[info] Take out [" << retVec.size() << "] messages from msgReceiving_");
    LOG_INFO("[info] Take out {0} messages from receiving cache", retVec.size());
    return retVec;
}

MessagePtr
ServiceHandler::SeizeOneSendMessage()
{
    std::unique_lock<std::mutex> lk_msg_vec{mutexOfSending_};
    //DEBUG("[info] wait msgToSend_");
    LOG_INFO("[info] wait msgToSend_");
    cvSend_.wait(lk_msg_vec, [&] { return !msgToSend_.empty(); });
    //DEBUG("[info] Take message from msgToSend_")
    LOG_INFO("[info] Take message from msgToSend_");
    const auto reply = std::dynamic_pointer_cast<bolean::websocket::MetaData>(msgToSend_.front());
    msgToSend_.erase(msgToSend_.begin());
    lk_msg_vec.unlock();

    // add message id to unreply list
    if (reply->type_info() != bolean::websocket::MsgType::REPLY)
    {
        std::unique_lock<std::mutex> lk_reply{mutexOfUnreplying_};
        // FIXME: change unreply to a `set`
        msgUnreply_.insert(reply->message_id());
    }
    return reply;
}

std::string
ServiceHandler::SeizeOneSendMessageAsString()
{
    const auto msgPtr = SeizeOneSendMessage();
    if (!msgPtr)
        return {};
    return msgPtr->SerializeAsString();
}


[[noreturn]] void
ServiceHandler::AddSendMessage(const MessagePtr& msgPtr)
{
    LOG_DEBUG("add a message to msgToSend_");
    std::unique_lock<std::mutex> lk{mutexOfSending_};
    msgToSend_.emplace_back(msgPtr);
    cvSend_.notify_one();
}

[[noreturn]] void
ServiceHandler::AddRecvMessage(const MessagePtr& msgPtr)
{
    LOG_DEBUG("add a newly received message by ptr");
    std::unique_lock<std::mutex> lk{mutexOfReceiving_};
    LOG_INFO("receivcing vec size={0}", msgReceiving_.size());
    msgReceiving_.emplace_back(msgPtr);
    cvRecv_.notify_one();
}


[[noreturn]] void
ServiceHandler::AddRecvMessage(const std::string& msgIn)
{
    //DEBUG("add a newly received message by string");
    LOG_DEBUG("add a newly received message by string");
    const MessagePtr msgPtr = std::make_shared<bolean::websocket::MetaData>();
    msgPtr->ParseFromString(msgIn);
    AddRecvMessage(msgPtr);
}

[[noreturn]] void
ServiceHandler::OnProcess()
{
    LOG_DEBUG("[info] message processing thread start");
    while (true)
    {
        auto msgVec = SeizeSomeRecvMessage();
        LOG_INFO("[info] This time I took out [{0}] messages ", msgVec.size());
        for (auto& msg : msgVec)
        {
            if (!msg) break;
            LOG_INFO("\n>>>\nNEW MESSAGE\n{0}<<<", msg->DebugString());
            const auto metadata = std::dynamic_pointer_cast<bolean::websocket::MetaData>(msg);
            if (metadata->type_info() == bolean::websocket::MsgType::REPLY)
            {
                ProcessOnEachMessage(metadata);
            }
            else
            {
                const uint32_t msgNo = metadata->message_id();
                //replyingPool_[msgNo] = std::async(std::launch::async, &ServiceHandler::ProcessOnEachMessage,
                //                                  shared_from_this(), msg);

                auto msgRes = std::async(std::launch::async, &ServiceHandler::ProcessOnEachMessage,
                                         shared_from_this(), msg);
                std::unique_lock<std::mutex> lk(mutexOfResultPool_);
                replyingPol_.emplace_back(msgNo, std::move(msgRes));
                lk.unlock();
                cvResult_.notify_one();
            }
        }
    }
}

// Message here are origin message => MetaData
MessagePtr
ServiceHandler::ProcessOnEachMessage(const MessagePtr& msgPtr) const
{
    if (!VerificationCheck(msgPtr))
    {
        LOG_ERROR("[error] {0} Message broken", __func__);
        const auto reply = std::make_shared<bolean::websocket::Reply>();
        reply->set_ret_code(-1);
        return reply;
    }
    const auto metaMessage = std::dynamic_pointer_cast<bolean::websocket::MetaData>(msgPtr);
    if (!metaMessage)
    {
        //DEBUG("[error] [" << __func__ << "] Msg Cast Error");
        LOG_ERROR("[error] {0} Msg Cast Error", __func__);
        const auto reply = std::make_shared<bolean::websocket::Reply>();
        reply->set_ret_code(-1);
        return reply;
    }
    // Preprocess for internal message
    const auto internalMessage = MessageYeildingHelper::YeildCorrespondingMessageFromType(metaMessage->type_info());
    if (internalMessage->ParseFromString(metaMessage->data_content()))
    {
        return dispatcher_->onProtobufMessage(internalMessage);
    }

    // possibly unable to reach, just for safety
    const auto reply = std::make_shared<bolean::websocket::Reply>();
    reply->set_ret_code(-1);
    return reply;
}

int
ServiceHandler::OnRePly()
{
    // no data race
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> processQueue;
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> tmpMap;
    while (true)
    {
        if (processQueue.empty())
        {
            tmpMap = TakeReplysBlock();
        }
        // In this case, there still remain tasks to 
        // be examined whether been completed or not.
        // so we can't blockly take massages from the
        // `future-pool`, just quickly give it a glance
        // and go back here as soon as possible to
        // deal with the existed tasks.
        else
        {
            tmpMap = TakeReplysNoBlock();
        }

        if (!tmpMap.empty())
        {
            //DEBUG("[info] swapped pool size [" << tmpMap.size() << "]");
            LOG_INFO("[info] swapped pool size {0}", tmpMap.size());
            for (auto& ele : tmpMap)
            {
                processQueue.emplace_back(std::move(ele));
            }
        }

        for (auto iter = processQueue.begin(); iter != processQueue.end();)
        {
            // for every action check 10ms if its status get ready
            if (iter->second.wait_for(std::chrono::milliseconds(10)) == std::future_status::ready)
            {
                //DEBUG("[info] task process finished");
                LOG_DEBUG("[info] task process finished");
                // wrap and reply and delete
                const auto originId = iter->first;
                const auto retMsg = iter->second.get();

                auto replyMsg = std::dynamic_pointer_cast<bolean::websocket::Reply>(retMsg);
                if (!replyMsg)
                {
                    ReplyCurrentMessage(retMsg);
                }

                // Add its origin id after tasks done
                replyMsg->set_origin_id(originId);
                //DEBUG("[info] origin_id=[" << originId << "], ret_code=[" << replyMsg->ret_code() << "]");
                LOG_INFO("\n>>>\n[info] origin_id=[{0}], ret_code=[{1}]\n<<<", originId, replyMsg->ret_code());
                ReplyCurrentMessage(replyMsg);
                iter = processQueue.erase(iter);
            }
            else
            {
                ++iter;
            }
        }
    }
}

std::vector<std::pair<uint32_t, std::future<MessagePtr>>>
ServiceHandler::TakeReplysBlock()
{
    //DEBUG("[info] swap replying pool blockable")
    LOG_DEBUG("[info] swap replying pool blockable");
    std::unique_lock<std::mutex> lk(mutexOfResultPool_);
    cvResult_.wait(lk, [&] { return !replyingPol_.empty(); });
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> tmpMap{std::move(replyingPol_)};
    replyingPol_.clear();
    lk.unlock();
    return tmpMap;
}


std::vector<std::pair<uint32_t, std::future<MessagePtr>>>
ServiceHandler::TakeReplysNoBlock()
{
    //DEBUG("[info] swap replying pool unblockable")
    LOG_INFO("[info] swap replying pool unblockable");
    if (replyingPol_.empty())
        return {};
    std::unique_lock<std::mutex> lk(mutexOfResultPool_, std::defer_lock);
    if (!lk.try_lock())
    {
        return {};
    }
    if (replyingPol_.empty())
        return {};
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> tmpMap{std::move(replyingPol_)};
    replyingPol_.clear();
    lk.unlock();
    return tmpMap;
}


int
ServiceHandler::OnUploads() const
{
    while (true)
    {
        std::this_thread::sleep_for(7s);
        auto winNT = sysinfo::win_nt::GetWendousInfo();
        LOG_INFO("\n>>>\n{0}\n<<<", winNT);
        auto NetCards = sysinfo::NetCardInfo::DumpInfo();
        for (auto card : NetCards)
        {
            LOG_INFO("\n>>>\nname:{0}\ndesc:{1}\nmac:{2}\n<<<",
                     card.net_card_name, card.net_card_desc, card.net_card_mac);
        }
    }
    return 0;
}

bool
ServiceHandler::CheckRegisterStatus() const
{
    //DEBUG("check regist status");
    LOG_DEBUG("check regist status");
    return authenticated_.load();
}

std::string
ServiceHandler::RegistRequest() const
{
    const auto registerRequest = std::make_shared<bolean::websocket::AutoRegisterRequest>();
    std::string machineCode;
    std::string mac;
    if (GetMachineCodeAndMac(machineCode, mac) == -1)
    {
        //DEBUG("GetMachineCode error");
        LOG_ERROR("GetMachineCode error");
        return {};
    }
    //DEBUG("machine_code=["<< machineCode << "] mac=[" << mac <<"]");
    LOG_INFO("\nmachine_code=[{0}] \nmac=[{1}]", machineCode, mac);
    registerRequest->set_serialize_number(machineCode);
    registerRequest->set_mac(mac);
    registerRequest->set_host("");
    const auto metadata = WrapAsMetadataMessage(registerRequest);
    return metadata->SerializeAsString();
}

int
ServiceHandler::CheckRegisterResponse(const std::string& msgString)
{
    bolean::websocket::MetaData md;
    if (!md.ParseFromString(msgString))
    {
        //std::cout << "[error] RegisterResponse parsing error";
        LOG_ERROR("[error] RegisterResponse parsing error");
        return -1;
    }
    //DEBUG("[info] parsed successfully!");
    LOG_DEBUG("[info] parsed successfully!");
    const auto msgPtr = MessageYeildingHelper::YeildCorrespondingMessageFromType(md.type_info());
    msgPtr->ParseFromString(md.data_content());

    LOG_INFO("[info] this is what we received:\n{0}", msgPtr->DebugString());
    const auto rspPtr = std::dynamic_pointer_cast<bolean::websocket::RegisterResponse>(msgPtr);
    if (!rspPtr)
    {
        //DEBUG("[error] Internal message type error");
        LOG_ERROR("[error] Internal message type error");
        return -1;
    }

    const auto& auth_code = rspPtr->auth_code();
    const auto& secret = rspPtr->secret();
    //DEBUG("[info] auth_code=" << auth_code << " secret=" << secret);
    LOG_INFO("[info] auth_code=[{0}] \nsecret=[{1}]", auth_code, secret);

    int status = AuthorizeFromNetwork(auth_code);
    //DEBUG("[info] register status = [" << status << "]");
    LOG_INFO("[info] register status = [{0}]", status);
    if (status == 0)
    {
        ApplyRegisterChanges(secret);
    }
    return status;
}

void
ServiceHandler::ApplyRegisterChanges(const std::string& secret)
{
    //DEBUG("[info] authenticated set to true!");
    LOG_DEBUG("[info] authenticated set to true!");
    authenticated_ = true;
    secret_ = secret;
}

std::string ServiceHandler::SelfVerify()
{
    bolean::websocket::MetaData md;
    md.set_message_id(MessageYeildingHelper::GetInstance().GenMsgNo());
    md.set_type_info(bolean::websocket::SELF_VARIFY);
    md.set_data_content(secret_);
    return md.SerializeAsString();
}

// check_sum compare
bool
ServiceHandler::VerificationCheck(const MessagePtr& msgPtr) const
{
    // reserved
    (void)msgPtr;
    return true;
}

void
ServiceHandler::ReplyCurrentMessage(const MessagePtr& msgPtr)
{
    //const auto reply = std::make_shared<bolean::websocket::Reply>();
    // todo: change return value to protobuf message*
    //reply->set_origin_id(msgId);
    //reply->set_ret_code(retCode);
    //reply->set_ret_info(retInfo);
    const auto metaMsg = WrapAsMetadataMessage(msgPtr);
    AddSendMessage(metaMsg);
}

void
ServiceHandler::RegisterHandler()
{
    // 自动注册请求
    dispatcher_->registerCallback<bolean::websocket::AutoRegisterRequest>(
        [&](const std::shared_ptr<bolean::websocket::AutoRegisterRequest>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.AutoRegisterRequest");
            LOG_INFO("[info] | Doing ... {AutoRegisterRequest}");
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(0);
            return reply;
        });

    // 注册返回消息
    dispatcher_->registerCallback<bolean::websocket::RegisterResponse>(
        [&](const std::shared_ptr<bolean::websocket::RegisterResponse>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.RegisterResponse");
            LOG_INFO("[info] | Doing ... {RegisterResponse}n");
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(0);
            return reply;
        });

    // REPLY
    dispatcher_->registerCallback<bolean::websocket::Reply>(
        [&](const std::shared_ptr<bolean::websocket::Reply>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.Reply");
            LOG_INFO("[info] | Doing ... {Reply}");
            msgUnreply_.erase(message->origin_id());
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(0);
            return reply;
        });

    // 策略下发
    dispatcher_->registerCallback<bolean::websocket::PolicyApply>(
        [&](const std::shared_ptr<bolean::websocket::PolicyApply>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.PolicyApply");
            LOG_INFO("[info] | Doing ... {PolicyApply}");
            const auto policyType = message->policy_type();
            auto& policyContent = message->policy_content();

            // restore policyContent
            const auto internalPolicy = MessageYeildingHelper::YeildCorrespondingMessageFromType(policyType);
            if (!internalPolicy)
            {
                LOG_INFO("message content type error");
                const auto reply = std::make_shared<bolean::websocket::Reply>();
                reply->set_ret_code(-1);
                reply->set_ret_info("message content type error on policy apply");
                return reply;
            }
            // handle sub-policy by themselves
            if (!internalPolicy->ParseFromString(policyContent))
            {
                LOG_INFO("message content has been broken");
                const auto reply = std::make_shared<bolean::websocket::Reply>();
                reply->set_ret_code(-1);
                reply->set_ret_info("policy-apply message content has been broken");
                return reply;
            }
            return dispatcher_->onProtobufMessage(internalPolicy);
            // 3333
        });

    // 策略下发->文件白名单
    dispatcher_->registerCallback<bolean::websocket::FileWhitelistPack>(
        [&](const std::shared_ptr<bolean::websocket::FileWhitelistPack>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.FileWhitelistPack");
            LOG_INFO("[info] | Doing ... {FileWhitelistPack}");
            auto action = static_cast<uint32_t>(message->action());
            const auto fileWhitelists = ResolveRepeatedFileWhitelist(message);
            const auto ret_code = ModifyWhiteListFromNetwork(static_cast<WHITELIST_ACTION>(action), fileWhitelists);
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("white list OK!");
            return reply;
        });

    // 策略下发->组策略
    dispatcher_->registerCallback<bolean::websocket::GroupPolicy>(
        [&](const std::shared_ptr<bolean::websocket::GroupPolicy>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.GroupPolicy");
            LOG_INFO("[info] | Doing ... {GroupPolicy}");
            const auto internalMesssage = MessageYeildingHelper::YeildCorrespondingMessageFromType(
                message->group_policy_type());
            if (!internalMesssage)
            {
                LOG_ERROR("message content type error");
                const auto reply = std::make_shared<bolean::websocket::Reply>();
                reply->set_ret_code(-1);
                reply->set_ret_info("Group_policy message content type error");
                return reply;
            }
            // handle by sub-groupPolicy itself
            if (!internalMesssage->ParseFromString(message->policy_content()))
            {
                LOG_ERROR("message content has been broken");
                const auto reply = std::make_shared<bolean::websocket::Reply>();
                reply->set_ret_code(-1);
                reply->set_ret_info("Group_policy message content has been broken");
                return reply;
            }
            return dispatcher_->onProtobufMessage(internalMesssage);
            // 5555
        });

    // 策略下发->组策略->账户策略
    dispatcher_->registerCallback<bolean::websocket::AccountPolicy>(
        [&](const std::shared_ptr<bolean::websocket::AccountPolicy>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.AccountPolicy");
            LOG_INFO("[info] | Doing ... {AccountPolicy}");

            ACCOUNT_POLICY_MESSAGE ape{};
            ape.password_complex_constraint = message->password_complex_constraint();
            ape.password_minimum_length = message->password_minimum_length();
            ape.password_time_limitation = message->password_time_limitation();
            ape.histroical_password_count = message->histroical_password_count();
            ape.account_retry_times = message->account_retry_times();
            ape.enable_guest_account = message->enable_guest_account();

            const auto ret_code = ApplyAccountPolicyFromNetwork(ape);
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("Account policy ok!");
            return reply;
        });

    // 策略下发->组策略->审核策略 
    dispatcher_->registerCallback<bolean::websocket::AuditPolicy>(
        [&](const std::shared_ptr<bolean::websocket::AuditPolicy>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.AuditPolicy");
            LOG_INFO("[info] | Doing ... {AuditPolicy}");

            AUDIT_POLICY_MESSAGE apm{};
            apm.modify = message->modify();
            apm.login_event = message->login_event();
            apm.object_access = message->object_access();
            apm.privilege_apply = message->privilege_apply();
            apm.system_event = message->system_event();
            apm.account_login = message->account_login();
            apm.account_management = message->account_management();

            const auto ret_code = ApplyAuditPolicyFromNetwork(apm);
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("Audit Policy Ok!");
            return reply;
        });

    // 策略下发->组策略->安全选项
    dispatcher_->registerCallback<bolean::websocket::SecurityOption>(
        [&](const std::shared_ptr<bolean::websocket::SecurityOption>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.SecurityOption");
            LOG_INFO("[info] | Doing ... {SecurityOption}");

            SECURITY_OPTION_MESSAGE som{};
            som.shutdown_with_clearance = message->shutdown_with_clearance();
            som.interactive_login_without_display = message->interactive_login_without_display();
            som.interactive_login_without_C_A_D = message->interactive_login_without_c_a_d();
            som.reject_anonymous_enumeration_by_SAM = message->reject_anonymous_enumeration_by_sam();
            som.reject_anonymous_enumeration_by_SAM_or_sharing = message->
                reject_anonymous_enumeration_by_sam_or_sharing();
            som.autoplay = message->autoplay();
            som.shared_by_default = message->shared_by_default();

            const auto ret_code = ApplySecurityOptionFromNetwork(som);
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("SecurityOption ok!");
            return reply;
        });

    // 策略下发->系统设置
    dispatcher_->registerCallback<bolean::websocket::SysSetting>(
        [&](const std::shared_ptr<bolean::websocket::SysSetting>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.SysSetting");
            LOG_INFO("[info] | Doing ... {SysSetting}");

            SYSTEM_CONFIG_MESSAGE scm;
            scm.whitelist_protection = message->whitelist_protection();
            scm.mode_of_whitelist_protection = message->mode_of_whitelist_protection();
            scm.bubble_alarm = message->bubble_alarm();
            scm.self_protection = message->self_protection();
            const auto ret_code = ApplySystemConfigFromNetwork(scm);
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("System successfully settled");
            return reply;
        });

    // 策略下发->U盘管理
    dispatcher_->registerCallback<bolean::websocket::UsbSetting>(
        [&](const std::shared_ptr<bolean::websocket::UsbSetting>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.UsbSetting");
            LOG_INFO("[info] | Doing ... {UsbSetting}");

            const auto ret_code = SwitchUsbManageFromNetwork(message->usb_management_switch());
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("USB successfully settled");
            return reply;
        });

    // 策略下发->主机保护
    dispatcher_->registerCallback<bolean::websocket::HostProtection>(
        [&](const std::shared_ptr<bolean::websocket::HostProtection>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.HostProtection");
            LOG_INFO("[info] | Doing {HostProtection}");
            const auto ret_code = SwitchFileProtectionFromNetwork(message->switch_());
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("Host protection successfully settled");
            return reply;
        });

    // 策略下发->注册表保护
    dispatcher_->registerCallback<bolean::websocket::RegProtection>(
        [&](const std::shared_ptr<bolean::websocket::RegProtection>& message)-> MessagePtr
        {
            assert(message->GetDescriptor()->full_name() == "bolean.websocket.RegProtection");
            LOG_INFO("[info] | Doing {HostProtection}");
            const auto ret_code = SwitchRegProtectionFromNetwork(message->switch_());
            const auto reply = std::make_shared<bolean::websocket::Reply>();
            reply->set_ret_code(ret_code);
            reply->set_ret_info("Registy Protection settled!");
            return reply;
        });
}
