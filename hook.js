
function disa(address, number) {
    console.log('star disamble address : ', address);
    for (var i = 0; i < number; i++) {
        var ins = Instruction.parse(address);
        // console.log('=====================');
        // console.log("address: " + address);
        // console.log("ins.size: " + ins.size);
        // console.log("ins.mnemonic: " + ins.mnemonic);
        // console.log("ins.opStr: " + ins.opStr);
        // console.log("ins.operands: " + ins.operands);
        // console.log("ins.regsRead: " + ins.regsRead);
        // console.log("ins.regsWritten: " + ins.regsWritten);
        // console.log("ins.groups: " + ins.groups);



        // ins.size：该指令的大小
        // ins.mnemonic：指令助记符的字符串表示形式
        // ins.opStr：指令操作数字符串
        // ins.operands：描述每个操作数的对象数组，每个操作数至少指定类型和值，还可能根据体系结构指定其他属性
        // ins.regsRead：该指令隐式读取的寄存器名称数组
        // ins.regsWritten：该指令隐式写入的寄存器名称数组
        // ins.groups：该指令所属的组名数组
        // instoString()：转换为人类可读字符串

        console.log("instoString(): " + ins.toString());
        address = ins.next;
    }
}
function hook_callfuntion() {

    var linker = Process.findModuleByName("linker")

    if (linker == null) {

        console.log("linker is null");
    }
    var symbols = linker.enumerateSymbols()
    // __dl__ZL13call_functionPKcPFviPPcS2_ES0
    // static void call_function(const char* function_name__unused,inker_ctor_function_t function,const char* realpath __unused

    symbols.forEach(function (symbol) {
        // 先 hook linker 的call_function 找到正确的加载时机
        if (symbol.name.includes("call_function") >= 1) {
            Interceptor.attach(symbol.address, {
                onEnter: function (args) {


                    var sopath = Memory.readCString(args[2])
                    if (sopath.includes("libnative-lib.so") >= 1) {
                        console.log(symbol.name);
                        console.log("function_name : " + Memory.readCString(args[0]));
                        console.log("function " + Memory.readCString(args[1]));
                        console.log("realpath " + Memory.readCString(args[2]));
                        // 说明这个库已经加载好了，
                        var libnative = Process.findModuleByName("libnative-lib.so")
                        console.log("libnative : " + libnative.base);
                        //thumb 指令需要 多加 1

                        // disa(libnative.base.add(0x92c2).add(1), 10)
                        // disa(libnative.base.add(0x93ce).add(1), 10)
                        // disa(libnative.base.add(0x9498).add(1), 10)
                        //找到 exit/kill的相对地址，进行patch 
                        Memory.protect(libnative.base.add(0x92c2), 4, "rwx")
                        libnative.base.add(0x92c2).writeByteArray([0x00, 0xbf, 0x00, 0xbf])

                  


                        // Memory.protect(libnative.base.add(0x93ce), 4, "rwx")
                        // libnative.base.add(0x93ce).writeByteArray([0x00, 0xbf, 0x00, 0xbf])

                         
                        Memory.patchCode(libnative.base.add(0x93ce), 4, code => {
                            // const cw = new X86Writer(code, { pc: getLivesLeft });
                            // cw.putMovRegU32('eax', 9000);
                            // cw.putRet();
                            var cw = new ThumbWriter(libnative.base.add(0x93ce))
                            cw.putNop()
                            cw = new ThumbWriter(libnative.base.add(0x93ce).add(0x02))
                            cw.putNop()
                            cw.flush();
                        });

                        // Memory.protect(libnative.base.add(0x9498), 4, "rwx")
                        // libnative.base.add(0x9498).writeByteArray([0x00, 0xbf, 0x00, 0xbf])
                        console.log("before patch")
                        disa(libnative.base.add(0x9498).add(1), 10)
                        Memory.patchCode(libnative.base.add(0x9498), 4, code => {
                            // const cw = new X86Writer(code, { pc: getLivesLeft });
                            // cw.putMovRegU32('eax', 9000);
                            // cw.putRet();
                            var cw = new ThumbWriter(libnative.base.add(0x9498))
                            cw.putNop()
                            cw = new ThumbWriter(libnative.base.add(0x9498).add(0x02))
                            cw.putNop()
                            cw.flush();
                        });

                        console.log("after patch")
                        disa(libnative.base.add(0x9498).add(1), 10)
                    }

                }, onLeave: function (args) {

                }
            })

        }


    })

}

function hook() {

    var targetso = Process.getModuleByName("libnative.so")
    if (targetso != null) {
        console.log("so not found ")
    }
    var exports = targetso.enumerateExports()
    exports.forEach(function (ex) {

        //if (ex.name.includes("strstr") >= 1) {
        console.log("export name:" + ex.name + "  export address" + ex.address)

        //disa(ex.address,10)
        // }


    }
    )

}





setImmediate(hook_callfuntion)