simple device
{
    @display("i=device/cpu;p=230,40");
    gates:
        input in;
        output out;
}

simple server
{
    @display("i=abstract/router");
    gates:
        input in;
        output out;
}

network Network
{
    @display("bgb=283,147");
    submodules:
        Device: device {
            @display("p=70.215004,61.91");
        }
        Server: server {
            @display("p=192.525,62.665");
        }
    connections:
        Device.out --> {  delay = 10ms; } --> Server.in;
        Device.in <-- {  delay = 10ms; } <-- Server.out;
}

