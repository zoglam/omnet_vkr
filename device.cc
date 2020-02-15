#include <omnetpp.h>
#include "ecc.h"
#include "md5.h"
#include <iostream>
#include <stdint.h>
#include <string.h>
using namespace omnetpp;

enum nextStep
{
    Step1, Step2, Step3
};

class device : public cSimpleModule
{
private:
    cMessage *msg;                          // Данные для отправки через cMessage
    unsigned char p_publicKey[ECC_BYTES + 1];     // Public key
    unsigned char p_privateKey[ECC_BYTES];        // Private key
    unsigned char p_hash[ECC_BYTES];              // Хэш
    unsigned char p_signature[ECC_BYTES * 2];     // Подпись
    std::string indicatorInfoHash;          // Показания счетчика Hash
    std::string indicatorInfo;              // Показания счетчика
    nextStep currentStep;                   // Текущий этап алгоритма
    int functionStateReturn = 0;
    unsigned char *duplicate;
    unsigned int i = 0;
    char *converted;
protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);
};

Define_Module(device);

void device::initialize()
{
    nextStep currentStep = Step1;
    functionStateReturn = ecc_make_key(p_publicKey, p_privateKey);                  // Create Public and Private keys
    EV << "Keys created?(1|0): " << functionStateReturn << endl;
    EV << "Created p_publicKey : " << p_publicKey << endl;
    EV << "Created p_privateKey: " << p_privateKey << endl;
    duplicate = p_publicKey;
    converted = reinterpret_cast<char*>(duplicate);                                 // unsigned char -> char
    msg = new cMessage(converted);
    scheduleAt(simTime() + dblrand(), msg->dup());
}

void device::handleMessage(cMessage *msg)
{
    cModule *target;
    target = getParentModule()->getSubmodule("Server");
    switch (currentStep) {
        case Step1:
            sendDirect(msg, target, "radioIn");
            currentStep = Step2;
            return;
        case Step2:
            indicatorInfo = "80";
            indicatorInfoHash = md5(indicatorInfo);                                 // MD5
            strcpy((char*) p_hash, indicatorInfoHash.c_str());                      // string -> unsigned char
            EV << "Created p_hash: " << p_hash << endl;
            msg = new cMessage(indicatorInfoHash.c_str());
            scheduleAt(simTime() + dblrand(), msg->dup());
            sendDirect(msg, target, "radioIn");
            currentStep = Step3;
            return;
        case Step3:
            functionStateReturn = ecdsa_sign(p_privateKey, p_hash, p_signature);    // Create signature
            EV << "Signature created?(1|0): " << functionStateReturn << endl;
            duplicate = p_signature;
            converted = reinterpret_cast<char*>(duplicate);                         // unsigned char -> char
            msg = new cMessage(converted);
            scheduleAt(simTime() + dblrand(), msg->dup());
            sendDirect(msg, target, "radioIn");
            currentStep = Step1;
            return;
    }
}
