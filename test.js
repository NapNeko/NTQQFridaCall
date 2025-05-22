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
    // 1. wrapper.node获取基址
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }

    // 2. 获取napi相关导出函数地址
    var napi_call_function = Module.findExportByName('qqnt.dll', 'napi_call_function');
    var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
    var napi_create_object = Module.findExportByName('qqnt.dll', 'napi_create_object');
    var napi_create_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_create_string_utf8');
    var napi_set_named_property = Module.findExportByName('qqnt.dll', 'napi_set_named_property');
    var napi_get_boolean = Module.findExportByName('qqnt.dll', 'napi_get_boolean');
    var napi_create_function = Module.findExportByName('qqnt.dll', 'napi_create_function');
    var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');

    // 3. 构造NativeFunction对象
    var napi_get_cb_info_fn = new NativeFunction(
        napi_get_cb_info, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
    );
    var napi_create_object_fn = new NativeFunction(
        napi_create_object, 'int',
        ['pointer', 'pointer']
    );
    var napi_create_string_utf8_fn = new NativeFunction(
        napi_create_string_utf8, 'int',
        ['pointer', 'pointer', 'ulong', 'pointer']
    );
    var napi_set_named_property_fn = new NativeFunction(
        napi_set_named_property, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer']
    );
    var napi_get_boolean_fn = new NativeFunction(
        napi_get_boolean, 'int',
        ['pointer', 'int', 'pointer']
    );
    var napi_call_function_fn = new NativeFunction(
        napi_call_function, 'int',
        ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'pointer']
    );
    var napi_create_function_fn = new NativeFunction(
        napi_create_function, 'int',
        ['pointer', 'pointer', 'size_t', 'pointer', 'pointer', 'pointer']
    );
    var napi_get_named_property_fn = new NativeFunction(
        napi_get_named_property, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer']
    );

    var napi_create_int32 = Module.findExportByName('qqnt.dll', 'napi_create_int32'); // 新增
    var napi_create_int32_fn = new NativeFunction( // 新增
        napi_create_int32, 'int',
        ['pointer', 'int', 'pointer']
    );

    // 4. 目标native函数地址（sub_181121B4E）
    var native_func_addr = baseAddr.add(0x1121B4E);

    // 5. 定义then回调native函数
    // NativeCallback实现
    var then_callback = new NativeCallback(function (env, info) {
        // 获取回调参数
        var argc_ptr = Memory.alloc(8);
        argc_ptr.writeU64(1);
        var argv_ptr = Memory.alloc(Process.pointerSize);
        var this_ptr = Memory.alloc(Process.pointerSize);
        napi_get_cb_info_fn(env, info, argc_ptr, argv_ptr, this_ptr, ptr(0));
        var result_val = argv_ptr.readPointer();

        // 获取全局对象 globalThis
        var global_name = Memory.allocUtf8String("globalThis");
        var global_ptr = Memory.alloc(Process.pointerSize);
        var status_global = napi_get_named_property_fn(env, env /* 这里用env作为global对象指针可能不对，需用napi_get_global */, global_name, global_ptr);

        // 如果有napi_get_global，优先用
        var napi_get_global = Module.findExportByName('qqnt.dll', 'napi_get_global');
        if (napi_get_global) {
            var napi_get_global_fn = new NativeFunction(
                napi_get_global, 'int',
                ['pointer', 'pointer']
            );
            status_global = napi_get_global_fn(env, global_ptr);
        }
        var global_obj = global_ptr.readPointer();

        // 获取JSON对象
        var json_name = Memory.allocUtf8String("JSON");
        var json_ptr = Memory.alloc(Process.pointerSize);
        var status_json = napi_get_named_property_fn(env, global_obj, json_name, json_ptr);
        var json_obj = json_ptr.readPointer();

        // 获取stringify函数
        var stringify_name = Memory.allocUtf8String("stringify");
        var stringify_ptr = Memory.alloc(Process.pointerSize);
        var status_stringify = napi_get_named_property_fn(env, json_obj, stringify_name, stringify_ptr);
        var stringify_fn = stringify_ptr.readPointer();

        // 调用stringify(result_val)
        var stringify_argv = Memory.alloc(Process.pointerSize);
        stringify_argv.writePointer(result_val);
        var stringify_result_ptr = Memory.alloc(Process.pointerSize);
        var status_call = napi_call_function_fn(
            env,
            json_obj,
            stringify_fn,
            1,
            stringify_argv,
            stringify_result_ptr
        );
        if (status_call === 0) {
            // 获取字符串内容
            var napi_get_value_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8');
            if (napi_get_value_string_utf8) {
                var napi_get_value_string_utf8_fn = new NativeFunction(
                    napi_get_value_string_utf8, 'int',
                    ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']
                );
                var buf = Memory.alloc(1024);
                var copied = Memory.alloc(8);
                napi_get_value_string_utf8_fn(env, stringify_result_ptr.readPointer(), buf, 1023, copied);
                var jsStr = buf.readUtf8String();
                console.log('[Promise result as JSON] ' + jsStr);
            }
        } else {
            console.log('[!] JSON.stringify call failed: ' + status_call);
        }
        return 0;
    }, 'int', ['pointer', 'pointer']);
    // 6. 创建then回调JS函数
    function createThenCallback(env) {
        var cb_ptr = Memory.alloc(Process.pointerSize);
        var cb_name = Memory.allocUtf8String("thenCallback");
        var status = napi_create_function_fn(
            env,
            cb_name,
            12,
            then_callback,
            ptr(0),
            cb_ptr
        );
        if (status !== 0) {
            console.log('[!] napi_create_function (thenCallback) failed: ' + status);
            return null;
        }
        return cb_ptr.readPointer();
    }

    console.log('[+] wrapper.node baseAddr: ' + baseAddr);

    // 7. hook 0x11133F4，获取napi_env和this
    let sub_11133F4 = baseAddr.add(0x11133F4);
    Interceptor.attach(sub_11133F4, {
        onEnter: function (args) {
            napi_env_ptr = args[0];
            console.log('napi_env (arg0) address: ' + args[0]);
            console.log('napi_callback_info (arg1) address: ' + args[1]);

            var this_arg_ptr = Memory.alloc(Process.pointerSize);
            var status = napi_get_cb_info_fn(
                args[0], args[1],
                ptr(0), ptr(0),
                this_arg_ptr, ptr(0)
            );
            var js_this = this_arg_ptr.readPointer();
            console.log('[*] napi_get_cb_info status: ' + status);
            console.log('[*] js_this: ' + js_this);
            var obj1_ptr = Memory.alloc(Process.pointerSize);
            napi_create_object_fn(napi_env_ptr, obj1_ptr);
            var obj1 = obj1_ptr.readPointer();

            var key_chatType = Memory.allocUtf8String("chatType");
            var val_chatType_ptr = Memory.alloc(Process.pointerSize);
            var status_chatType = napi_create_int32_fn( // 改为创建数字2
                napi_env_ptr,
                2,
                val_chatType_ptr
            );
            if (status_chatType !== 0) {
                console.log('[!] napi_create_int32_fn(chatType) failed: ' + status_chatType);
            }
            var val_chatType = val_chatType_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj1, key_chatType, val_chatType);

            var key_guildId = Memory.allocUtf8String("guildId");
            var guildIdStr = "";
            var guildIdBuf = Memory.allocUtf8String(guildIdStr);
            var guildIdLen = guildIdStr.length;
            var val_guildId_ptr = Memory.alloc(Process.pointerSize);
            var status_guildId = napi_create_string_utf8_fn(
                napi_env_ptr,
                guildIdBuf,
                guildIdLen,
                val_guildId_ptr
            );
            if (status_guildId !== 0) {
                console.log('[!] napi_create_string_utf8_fn(guildId) failed: ' + status_guildId);
            }
            var val_guildId = val_guildId_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj1, key_guildId, val_guildId);

            var key_peerUid = Memory.allocUtf8String("peerUid");
            var peerUidStr = "819085771";
            var peerUidBuf = Memory.allocUtf8String(peerUidStr);
            var peerUidLen = peerUidStr.length;
            var val_peerUid_ptr = Memory.alloc(Process.pointerSize);
            var status_peerUid = napi_create_string_utf8_fn(
                napi_env_ptr,
                peerUidBuf,
                peerUidLen,
                val_peerUid_ptr
            );
            if (status_peerUid !== 0) {
                console.log('[!] napi_create_string_utf8_fn(peerUid) failed: ' + status_peerUid);
            }
            var val_peerUid = val_peerUid_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj1, key_peerUid, val_peerUid);

            // 第二个object参数
            var obj2_ptr = Memory.alloc(Process.pointerSize);
            napi_create_object_fn(napi_env_ptr, obj2_ptr);
            var obj2 = obj2_ptr.readPointer();

            var key_busiId = Memory.allocUtf8String("busiId");
            var val_busiId_ptr = Memory.alloc(Process.pointerSize);
            var status_busiId = napi_create_int32_fn( // 改为创建数字2201
                napi_env_ptr,
                2201,
                val_busiId_ptr
            );
            if (status_busiId !== 0) {
                console.log('[!] napi_create_int32_fn(busiId) failed: ' + status_busiId);
            }
            var val_busiId = val_busiId_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj2, key_busiId, val_busiId);

            var key_jsonStr = Memory.allocUtf8String("jsonStr");
            var jsonStr = '{\"align\":\"center\",\"items\":[{\"txt\":\"下一秒起床通过王者荣耀加入群\",\"type\":\"nor\"}]}';
            var jsonStrBuf = Memory.allocUtf8String(jsonStr);
            var jsonStrLen = jsonStr.length;
            var val_jsonStr_ptr = Memory.alloc(Process.pointerSize);
            var status_jsonStr = napi_create_string_utf8_fn(
                napi_env_ptr,
                jsonStrBuf,
                jsonStrLen,
                val_jsonStr_ptr
            );
            if (status_jsonStr !== 0) {
                console.log('[!] napi_create_string_utf8_fn(jsonStr) failed: ' + status_jsonStr);
            }
            var val_jsonStr = val_jsonStr_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj2, key_jsonStr, val_jsonStr);

            var key_recentAbstract = Memory.allocUtf8String("recentAbstract");
            var recentAbstractStr = "这是最近的摘要";
            var recentAbstractBuf = Memory.allocUtf8String(recentAbstractStr);
            var recentAbstractLen = recentAbstractStr.length;
            var val_recentAbstract_ptr = Memory.alloc(Process.pointerSize);
            var status_recentAbstract = napi_create_string_utf8_fn(
                napi_env_ptr,
                recentAbstractBuf,
                recentAbstractLen,
                val_recentAbstract_ptr
            );
            if (status_recentAbstract !== 0) {
                console.log('[!] napi_create_string_utf8_fn(recentAbstract) failed: ' + status_recentAbstract);
            }
            var val_recentAbstract = val_recentAbstract_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj2, key_recentAbstract, val_recentAbstract);

            var key_isServer = Memory.allocUtf8String("isServer");
            var bool_isServer_ptr = Memory.alloc(Process.pointerSize);
            napi_get_boolean_fn(napi_env_ptr, 0, bool_isServer_ptr);
            var bool_isServer = bool_isServer_ptr.readPointer();
            napi_set_named_property_fn(napi_env_ptr, obj2, key_isServer, bool_isServer);

            // 两个bool参数
            var bool1_ptr = Memory.alloc(Process.pointerSize);
            var bool2_ptr = Memory.alloc(Process.pointerSize);
            napi_get_boolean_fn(napi_env_ptr, 1, bool1_ptr);
            napi_get_boolean_fn(napi_env_ptr, 1, bool2_ptr);
            var bool1 = bool1_ptr.readPointer();
            var bool2 = bool2_ptr.readPointer();

            // argv
            var argv = Memory.alloc(Process.pointerSize * 4);
            argv.add(0).writePointer(obj1);
            argv.add(Process.pointerSize).writePointer(obj2);
            argv.add(Process.pointerSize * 2).writePointer(bool1);
            argv.add(Process.pointerSize * 3).writePointer(bool2);

            // 创建native function
            var func_ptr = Memory.alloc(Process.pointerSize);
            var func_name = Memory.allocUtf8String("nativeFunc");
            var create_status = napi_create_function_fn(
                napi_env_ptr,
                func_name,
                10,
                native_func_addr,
                ptr(0),
                func_ptr
            );
            if (create_status !== 0) {
                console.log('[!] napi_create_function failed: ' + create_status);
                return;
            }
            var func = func_ptr.readPointer();

            // 调用napi_call_function，返回Promise
            var result_ptr = Memory.alloc(Process.pointerSize);
            var call_status = napi_call_function_fn(
                napi_env_ptr,
                js_this,
                func,
                4,
                argv,
                result_ptr
            );
            console.log('[*] napi_call_function status: ' + call_status);
            var promise_obj = result_ptr.readPointer();
            console.log('[*] napi_call_function result (Promise): ' + promise_obj);

            // 获取Promise的then方法
            var key_then = Memory.allocUtf8String("then");
            var then_fn_ptr = Memory.alloc(Process.pointerSize);
            var get_then_status = napi_get_named_property_fn(
                napi_env_ptr,
                promise_obj,
                key_then,
                then_fn_ptr
            );
            if (get_then_status !== 0) {
                console.log('[!] napi_get_named_property_fn(then) failed: ' + get_then_status);
                return;
            }
            var then_fn = then_fn_ptr.readPointer();

            // 创建then回调
            var then_cb = createThenCallback(napi_env_ptr);
            if (!then_cb) return;

            // 调用then方法
            var then_argv = Memory.alloc(Process.pointerSize);
            then_argv.writePointer(then_cb);
            var then_result_ptr = Memory.alloc(Process.pointerSize);
            var then_call_status = napi_call_function_fn(
                napi_env_ptr,
                promise_obj,
                then_fn,
                1,
                then_argv,
                then_result_ptr
            );
            console.log('[*] napi_call_function (then) status: ' + then_call_status);
        },
        onLeave: function (retval) {
            console.log('[+] sub_11133F4 return value: ' + retval);
        }
    });
}

main();