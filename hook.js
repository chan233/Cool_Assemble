
function disa(address, number) {
    console.log('star disamble address : ',address);
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


function hook() {

    var targetso = Process.getModuleByName("libc.so")
    if (targetso != null) {
    }
    var exports = targetso.enumerateExports()
    exports.forEach(function (ex) {


        if (ex.name.includes("strstr") >= 1) {
            console.log("export name:" + ex.name + "  export address" + ex.address)

            disa(ex.address,10)
        }


    }
    )

}





setImmediate(hook)