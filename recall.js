function bytesToHex(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer)
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

let napi_env_ptr = null;

async function main() {
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }

    // jz -> jnz 去掉撤回通知逻辑
    const patchAddr = baseAddr.add(0x25BF57F);
    console.log("patchAddr:", patchAddr);
    Memory.protect(patchAddr, 1, 'rwx');
    const origByte = patchAddr.readU8();
    if (origByte !== 0x74) {
        console.log('警告：目标地址不是jz指令（0x74），实际为:', origByte.toString(16));
    } else {
        // 5. 写入0x75（jnz）
        patchAddr.writeU8(0x75);
        console.log('已将jz(0x74)修改为jnz(0x75)');
    }

    // [Msg] on grp recall nfy ! frm:{} to:{}, pr:{} seq:{} rd:{} t:{} op_uid:{} op_t:{} is_off:{} trl_flag:{}
    // 解析撤回事件
    var hookAddr = baseAddr.add(0x25BF4D3);
    console.log("hookAddr:", hookAddr);
    Interceptor.attach(hookAddr, {
        onEnter: function (args) {
            const peer_ptr = this.context.rbp.add(0x30);
            const peer = peer_ptr.add(0x1).readUtf8String();
            console.log("=> Group Recall");
            console.log("peer:", peer);

            const seq_ptr = this.context.rbp.add(0x80);
            const seq = seq_ptr.readU64();
            console.log("seq:", seq);

            console.log("<=");
        }
    });
}

main();