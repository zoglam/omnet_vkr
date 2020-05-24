#include <omnetpp.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include "ecc.h"
using namespace omnetpp;

typedef struct // size = 16*2 + 16
{
    uint8_t p_signature[ECC_BYTES * 2];                                       // Signature
    uint8_t p_hash[ECC_BYTES];                                                // Public key
} DEVICE_MSG;

enum nextStep
{
    Step1, Step2
};

class server : public cSimpleModule
{
private:
    cMessage *msg;
    DEVICE_MSG DeviceMsg; // packetData
    uint8_t *p_publicKey; // Public key
    uint8_t p_hash[ECC_BYTES]; // Hash
    uint8_t p_signature[ECC_BYTES * 2]; // Signature
    nextStep currentStep = Step1; // Current action
    char *duplicate; // Storage for message
protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);
};

Define_Module(server);

void server::initialize()
{
}

void server::handleMessage(cMessage *msg)
{
    cModule *target = getParentModule()->getSubmodule("Device");
    duplicate = (char*) msg->getName();  // get arrived message
    if(currentStep == Step1)
    {
        p_publicKey = reinterpret_cast<unsigned char*>(duplicate);
        EV << "New Public key in DB" << endl;
        send(msg, "out");
        currentStep = Step2;
        return;
    }
    else if(currentStep == Step2)
    {                                                // get arrived message
        memcpy((char*) &DeviceMsg, reinterpret_cast<unsigned char*>(duplicate), sizeof(DEVICE_MSG)); // full arrived message copy to structure
        memcpy(p_signature, DeviceMsg.p_signature, sizeof(p_signature));                           // signature from
        memcpy(p_hash, DeviceMsg.p_hash, sizeof(p_hash));

        EV << "Verify status is(1|0): "
                << ecdsa_verify(p_publicKey, DeviceMsg.p_hash, DeviceMsg.p_signature) << endl;

        currentStep = Step2;
        return;
    }
}
