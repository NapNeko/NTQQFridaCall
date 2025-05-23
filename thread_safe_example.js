// 该脚本用于演示如何在 Frida 实现跨线程触发JS回调 从而调用需要的函数
function bytesToHex(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer)
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

let tsfn_ptr = null;
let timer = null;

// NativeCallback 作为 JS 回调
const js_callback = new NativeCallback(function (env, js_cb, context, data) {
    console.log('[+] cb env:', env);
    console.log('[TSFN JS Callback] 收到回调');
    return 0;
}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

function startTimer(tsfn) {
    if (timer) return;
    const napi_call_threadsafe_function = Module.findExportByName('qqnt.dll', 'napi_call_threadsafe_function');
    if (!napi_call_threadsafe_function) {
        console.log('[!] napi_call_threadsafe_function not found');
        return;
    }
    const napi_call_threadsafe_function_fn = new NativeFunction(
        napi_call_threadsafe_function, 'int',
        ['pointer', 'pointer', 'int']
    );
    timer = setInterval(function () {
        const status = napi_call_threadsafe_function_fn(tsfn, ptr(0), 0);
        if (status !== 0) {
            console.log('[!] napi_call_threadsafe_function failed:', status);
        }
    }, 2000); // 每2秒
}

function main() {
    // 1. wrapper.node获取基址
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }
    console.log('[+] wrapper.node baseAddr: ' + baseAddr);

    // 2. hook 0x11133F4，创建tsfn并定时调用
    let sub_11133F4 = baseAddr.add(0x11133F4);
    Interceptor.attach(sub_11133F4, {
        onEnter: function (args) {
            if (tsfn_ptr) {
                startTimer(tsfn_ptr);
                return;
            }
            const napi_env_ptr = args[0];
            const napi_create_threadsafe_function = Module.findExportByName('qqnt.dll', 'napi_create_threadsafe_function');
            if (!napi_create_threadsafe_function) {
                console.log('[!] napi_create_threadsafe_function not found');
                return;
            }
            const napi_create_threadsafe_function_fn = new NativeFunction(
                napi_create_threadsafe_function, 'int',
                [
                    'pointer', // env
                    'pointer', // func
                    'pointer', // async_resource
                    'pointer', // async_resource_name
                    'size_t',  // max_queue_size
                    'int',     // initial_thread_count
                    'pointer', // thread_finalize_data
                    'pointer', // thread_finalize_cb
                    'pointer', // context
                    'pointer', // call_js_cb
                    'pointer'  // result
                ]
            );
            console.log('[+] env_ptr:', napi_env_ptr);
            const async_resource_name = Memory.allocUtf8String("frida_tsfn");
            const tsfn_result_ptr = Memory.alloc(Process.pointerSize);
            const status = napi_create_threadsafe_function_fn(
                napi_env_ptr,
                ptr(0), // func: NULL
                ptr(0), // async_resource
                async_resource_name,
                0,      // max_queue_size
                1,      // initial_thread_count
                ptr(0), // thread_finalize_data
                ptr(0), // thread_finalize_cb
                ptr(0), // context
                js_callback, // call_js_cb
                tsfn_result_ptr
            );
            if (status !== 0) {
                console.log('[!] napi_create_threadsafe_function failed:', status);
                return;
            }
            tsfn_ptr = tsfn_result_ptr.readPointer();
            console.log('[+] Created ThreadSafeFunction:', tsfn_ptr);
            startTimer(tsfn_ptr);
        },
        onLeave: function (retval) {
            // 可选：输出返回值
        }
    });
}

main();