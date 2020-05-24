#include <omnetpp.h>
#include <stdio.h>
#include "ecc.h"
#include <iostream>
#include <stdint.h>
using namespace omnetpp;

typedef struct // size = 16*2 + 16
{
    uint8_t p_signature[ECC_BYTES * 2];
    uint8_t p_hash[ECC_BYTES];
} DEVICE_MSG;

enum nextStep
{
    Step1, Step2
};

class device : public cSimpleModule
{
private:
    cMessage *msg;
    DEVICE_MSG DeviceMsg;
    uint8_t p_publicKey[ECC_BYTES + 1]; // Public key
    uint8_t p_privateKey[ECC_BYTES]; // Private key
    uint8_t p_hash[ECC_BYTES]; // Hash
    uint8_t p_signature[ECC_BYTES * 2]; // Signature
    nextStep currentStep; // Current action
    unsigned char *duplicate; // Storage for message
protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);
};

Define_Module(device);

void device::initialize()
{
    nextStep currentStep = Step1; // init currentStep
    EV << "Keys created?(1|0): "
            << ecc_make_key(p_publicKey, p_privateKey) << endl; // Create Public and Private keys
    msg = new cMessage(reinterpret_cast<char*>(p_publicKey)); // Create packet
    scheduleAt(simTime() + dblrand(), msg->dup()); // self-message
}

void device::handleMessage(cMessage *msg)
{
    cModule *target = getParentModule()->getSubmodule("Server");
    if(currentStep == Step1)
    {
        send(msg, "out");
        currentStep = Step2;
        return;
    }
    else if(currentStep == Step2)
    {
        char convertedMessage[sizeof(DEVICE_MSG)];
        for (unsigned int i = 0; i < sizeof(p_hash); i++)
        {
            p_hash[i] = 90;
        }
        memcpy(DeviceMsg.p_hash, p_hash, sizeof(p_hash));
        EV << "Signature created?(1|0): " <<
                ecdsa_sign(p_privateKey, p_hash, p_signature) << endl; // Create signature
        memcpy(DeviceMsg.p_signature, p_signature, sizeof(p_signature));
        memcpy(convertedMessage, (char*) &DeviceMsg, sizeof(DEVICE_MSG));

        msg = new cMessage(convertedMessage);
        send(msg, "out"); // send message
        scheduleAt(simTime() + dblrand(), msg->dup());
        currentStep = Step2;
        return;
    }
}
