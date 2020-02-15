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

class server : public cSimpleModule
{
private:
    cMessage *msg;
    unsigned char *p_publicKey;
    unsigned char *p_signature;
    unsigned char *p_hash;
    nextStep currentStep = Step1;
    int functionStateReturn = 0;
    unsigned int i = 0;
    char *duplicate;
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
            duplicate = (char*) msg->getName();                                     // get arrived massage
            p_publicKey = reinterpret_cast<unsigned char*>(duplicate);              // char -> unsigned char
            EV << "New Public key in DB: " << p_publicKey << endl;
            sendDirect(msg, target, "radioIn");
            currentStep = Step2;
            return;
        case Step2:
            duplicate = (char*) msg->getName();                                     // get arrived massage
            p_hash = reinterpret_cast<unsigned char*>(duplicate);                   // char -> unsigned char
            EV << "New Hash: " << p_hash << endl;
            msg = new cMessage(duplicate);
            sendDirect(msg, target, "radioIn");
            currentStep = Step3;
            return;
        case Step3:
            duplicate = (char*) msg->getName();                                     // get arrived massage
            p_signature = reinterpret_cast<unsigned char*>(duplicate);              // char -> unsigned char
            EV << "New Signature: " << p_signature << endl;
            functionStateReturn = ecdsa_verify(p_publicKey, p_hash, p_signature);   // Verify signature
            EV << "Verify status is(1|0): " << functionStateReturn << endl;
            sendDirect(msg, target, "radioIn");
            currentStep = Step1;
            return;
    }
}

