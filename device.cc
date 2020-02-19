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
    uint8_t p_publicKey[ECC_BYTES + 1];                                       // Public key
    uint8_t p_privateKey[ECC_BYTES];                                          // Private key
    uint8_t p_hash[ECC_BYTES];                                                // Hash
    uint8_t p_signature[ECC_BYTES * 2];                                       // Signature                                                      // Indicator info
    nextStep currentStep;
    int functionStateReturn = 0;
    unsigned char *duplicate;
    unsigned int i = 0;
    char *converted;
    char array[48];
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
            send(msg, "out");
            currentStep = Step2;
            return;
        case Step2:
            for (i = 0; i < sizeof(p_hash); i++) {
                p_hash[i] = 90;
            }

            memcpy(DeviceMsg.p_hash, p_hash, sizeof(p_hash));

            functionStateReturn = ecdsa_sign(p_privateKey, p_hash, p_signature);    // Create signature
            EV << "Signature created?(1|0): " << functionStateReturn << endl;
            memcpy(DeviceMsg.p_signature, p_signature, sizeof(p_signature));
            memcpy(array, (char*) &DeviceMsg, sizeof(DEVICE_MSG));
            msg = new cMessage(array);

            scheduleAt(simTime() + dblrand(), msg->dup());
            send(msg, "out");
            currentStep = Step2;
            return;
    }
}
