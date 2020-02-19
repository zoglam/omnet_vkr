#include <omnetpp.h>
#include "ecc.h"
#include <iostream>
#include <stdint.h>
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
    DEVICE_MSG DeviceMsg;
    uint8_t *p_publicKey;                                                     // Public key
    uint8_t p_hash[ECC_BYTES];                                                // Hash
    uint8_t p_signature[ECC_BYTES * 2];                                       // Signature
    nextStep currentStep = Step1;
    int functionStateReturn = 0;
    char *duplicate;

    uint8_t array[48];
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
    cModule *target;
    target = getParentModule()->getSubmodule("Device");
    switch (currentStep) {
        case Step1:
            duplicate = (char*) msg->getName();                                                             // get arrived message
            p_publicKey = reinterpret_cast<unsigned char*>(duplicate);
            EV << "New Public key in DB" << endl;
            sendDirect(msg, target, "radioIn");
            currentStep = Step2;
            return;
        case Step2:
            duplicate = (char*) msg->getName();                                                             // get arrived message
            memcpy((char*) &DeviceMsg, reinterpret_cast<unsigned char*>(duplicate), sizeof(DEVICE_MSG));    // full arrived message copy to structure
            memcpy(p_signature, DeviceMsg.p_signature, sizeof(p_signature));                                // signature from
            memcpy(p_hash, DeviceMsg.p_hash, sizeof(p_hash));

            functionStateReturn = ecdsa_verify(p_publicKey, DeviceMsg.p_hash, DeviceMsg.p_signature);                           // Verify signature
            EV << "Verify status is(1|0): " << functionStateReturn << endl;

            msg = new cMessage(duplicate);
            sendDirect(msg, target, "radioIn");
            currentStep = Step2;
            return;
    }
}

