simple device
{
    @display("i=device/cpu;p=230,40");
    gates:
        input radioIn @directIn;
}

simple server
{
    @display("i=abstract/router");
    gates:
        input radioIn @directIn;
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
}

