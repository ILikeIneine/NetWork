#pragma once
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <future>
#include "MessageDispatcher.hpp"

using MessageVec = std::vector<MessagePtr>;

class ServiceHandler : public std::enable_shared_from_this<ServiceHandler>
{
public:
    ServiceHandler();
    ~ServiceHandler();
    ServiceHandler(const ServiceHandler&) = delete;
    ServiceHandler(ServiceHandler&&) = delete;
    ServiceHandler& operator=(const ServiceHandler&) = delete;
    ServiceHandler& operator=(ServiceHandler&&) = delete;

    void Run();

    //+--------- MQ Actions -----------
    MessageVec SeizeSomeRecvMessage();
    MessagePtr SeizeOneSendMessage();
    std::string SeizeOneSendMessageAsString();
    void AddSendMessage(const MessagePtr&);
    void AddRecvMessage(const MessagePtr&);
    void AddRecvMessage(const std::string&);

    //+-------- Register & Verify -------
    std::string RegistRequest() const;
    std::string SelfVerify();
    bool CheckRegisterStatus() const;
    int CheckRegisterResponse(const std::string&);
    void ApplyRegisterChanges(const std::string&);

    //+-------- Process Message --------+
    //      here work as producer       |
    //----------------------------------+
    void OnProcess();
    MessagePtr ProcessOnEachMessage(const MessagePtr&) const;

    //+--------- Reply Center ----------+
    //      here work as consumer       |
    //----------------------------------+
    int OnRePly();
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> TakeReplysBlock();
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> TakeReplysNoBlock();

    //+--------- Upload Jobs -----------+
    int OnUploads() const;


private:
    bool VerificationCheck(const MessagePtr&) const;
    void ReplyCurrentMessage(const MessagePtr&);

    void RegisterHandler();

private:
    //Communication& communication_;
    MessageVec msgToSend_;    // actually metadata message
    MessageVec msgReceiving_; // actually metadata message as well
    //std::map<uint32_t, std::future<int>> replyingPool_;
    std::vector<std::pair<uint32_t, std::future<MessagePtr>>> replyingPol_;

    std::set<uint32_t> msgUnreply_;

    std::mutex mutexOfSending_;
    std::mutex mutexOfReceiving_;
    std::mutex mutexOfUnreplying_;
    std::mutex mutexOfResultPool_;

    std::condition_variable cvSend_;
    std::condition_variable cvRecv_;
    std::condition_variable cvResult_;

    // FIXME: ADD SIGNAL
    std::thread workThread_;  // producer
    std::thread replyThread_; // consumer

    std::shared_ptr<ProtobufDispatcher> dispatcher_;
    std::atomic<bool> authenticated_;

    std::string secret_;
};
