
function dis(address, number) {
    for (var i = 0; i < number; i++) {
        var ins = Instruction.parse(address);
        console.log("address:" + address + "--dis:" + ins.toString());
        address = ins.next;
    }
}


function hook() {

    var targetso = Process.getModuleByName("libc.so")
    if (targetso != null) {
    }
    var exports = targetso.enumerateExports()
    exports.forEach(function (ex) {

        console.log(ex.name)
        console.log(ex.address)

    }
    )

}
   




setImmediate(hook)