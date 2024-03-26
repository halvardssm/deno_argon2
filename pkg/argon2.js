

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

let cachedUint8Memory0 = null;

function getUint8Memory0() {
    if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

let cachedInt32Memory0 = null;

function getInt32Memory0() {
    if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
};

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length) >>> 0;
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len) >>> 0;

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3) >>> 0;
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}
/**
* @param {string} password
* @param {number | undefined} algo
* @param {HashOptions | undefined} params
* @returns {string}
*/
export function hash(password, algo, params) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        let ptr1 = 0;
        if (!isLikeNone(params)) {
            _assertClass(params, HashOptions);
            ptr1 = params.__destroy_into_raw();
        }
        wasm.hash(retptr, ptr0, len0, isLikeNone(algo) ? 3 : algo, ptr1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        deferred3_0 = r0;
        deferred3_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred3_0, deferred3_1);
    }
}

/**
* @param {string} password
* @param {string} password_hash
* @returns {number}
*/
export function verify(password, password_hash) {
    const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(password_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify(ptr0, len0, ptr1, len1);
    return ret;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}
/**
*/
export const Algorithm = Object.freeze({
/**
* Optimizes against GPU cracking attacks but vulnerable to side-channels.
*
* Accesses the memory array in a password dependent order, reducing the
* possibility of time–memory tradeoff (TMTO) attacks.
*/
Argon2d:0,"0":"Argon2d",
/**
* Optimized to resist side-channel attacks.
*
* Accesses the memory array in a password independent order, increasing the
* possibility of time-memory tradeoff (TMTO) attacks.
*/
Argon2i:1,"1":"Argon2i",
/**
* Hybrid that mixes Argon2i and Argon2d passes (*default*).
*
* Uses the Argon2i approach for the first half pass over memory and
* Argon2d approach for subsequent passes. This effectively places it in
* the "middle" between the other two: it doesn't provide as good
* TMTO/GPU cracking resistance as Argon2d, nor as good of side-channel
* resistance as Argon2i, but overall provides the most well-rounded
* approach to both classes of attacks.
*/
Argon2id:2,"2":"Argon2id", });
/**
*/
export class HashOptions {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_hashoptions_free(ptr);
    }
    /**
    * Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    *
    * Value is an integer in decimal (1 to 10 digits).
    * @returns {number}
    */
    get memory_cost() {
        const ret = wasm.__wbg_get_hashoptions_memory_cost(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    *
    * Value is an integer in decimal (1 to 10 digits).
    * @param {number} arg0
    */
    set memory_cost(arg0) {
        wasm.__wbg_set_hashoptions_memory_cost(this.__wbg_ptr, arg0);
    }
    /**
    * Number of iterations, between 1 and (2^32)-1.
    *
    * Value is an integer in decimal (1 to 10 digits).
    * @returns {number}
    */
    get time_cost() {
        const ret = wasm.__wbg_get_hashoptions_time_cost(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Number of iterations, between 1 and (2^32)-1.
    *
    * Value is an integer in decimal (1 to 10 digits).
    * @param {number} arg0
    */
    set time_cost(arg0) {
        wasm.__wbg_set_hashoptions_time_cost(this.__wbg_ptr, arg0);
    }
    /**
    * Degree of parallelism, between 1 and 255.
    *
    * Value is an integer in decimal (1 to 3 digits).
    * @returns {number}
    */
    get parallelism_cost() {
        const ret = wasm.__wbg_get_hashoptions_parallelism_cost(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * Degree of parallelism, between 1 and 255.
    *
    * Value is an integer in decimal (1 to 3 digits).
    * @param {number} arg0
    */
    set parallelism_cost(arg0) {
        wasm.__wbg_set_hashoptions_parallelism_cost(this.__wbg_ptr, arg0);
    }
    /**
    * Size of the output (in bytes).
    * @returns {number | undefined}
    */
    get output_length() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_hashoptions_output_length(retptr, this.__wbg_ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Size of the output (in bytes).
    * @param {number | undefined} arg0
    */
    set output_length(arg0) {
        wasm.__wbg_set_hashoptions_output_length(this.__wbg_ptr, !isLikeNone(arg0), isLikeNone(arg0) ? 0 : arg0);
    }
}

const imports = {
    __wbindgen_placeholder__: {
        __wbg_crypto_c48a774b022d20ac: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbindgen_is_object: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg_process_298734cf255a885d: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_versions_e2e78e134e3e5d01: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbg_node_1cd7a5d853dbea79: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbindgen_is_string: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
        __wbg_msCrypto_bcb970640f50a1e8: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_require_8f08ceecec0f4fee: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments) },
        __wbindgen_is_function: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbindgen_string_new: function(arg0, arg1) {
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbg_randomFillSync_dc1e9a60c158336d: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments) },
        __wbg_getRandomValues_37fa2ca9e4e07fab: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments) },
        __wbg_newnoargs_c9e6043b8ad84109: function(arg0, arg1) {
            const ret = new Function(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_call_557a2f2deacc4912: function() { return handleError(function (arg0, arg1) {
            const ret = getObject(arg0).call(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbg_self_742dd6eab3e9211e: function() { return handleError(function () {
            const ret = self.self;
            return addHeapObject(ret);
        }, arguments) },
        __wbg_window_c409e731db53a0e2: function() { return handleError(function () {
            const ret = window.window;
            return addHeapObject(ret);
        }, arguments) },
        __wbg_globalThis_b70c095388441f2d: function() { return handleError(function () {
            const ret = globalThis.globalThis;
            return addHeapObject(ret);
        }, arguments) },
        __wbg_global_1c72617491ed7194: function() { return handleError(function () {
            const ret = global.global;
            return addHeapObject(ret);
        }, arguments) },
        __wbindgen_is_undefined: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg_call_587b30eea3e09332: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments) },
        __wbg_buffer_55ba7a6b1b92e2ac: function(arg0) {
            const ret = getObject(arg0).buffer;
            return addHeapObject(ret);
        },
        __wbg_newwithbyteoffsetandlength_88d1d8be5df94b9b: function(arg0, arg1, arg2) {
            const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_new_09938a7d020f049b: function(arg0) {
            const ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_set_3698e3ca519b3c3c: function(arg0, arg1, arg2) {
            getObject(arg0).set(getObject(arg1), arg2 >>> 0);
        },
        __wbg_newwithlength_89eeca401d8918c2: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_subarray_d82be056deb4ad27: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbindgen_throw: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbindgen_memory: function() {
            const ret = wasm.memory;
            return addHeapObject(ret);
        },
    },

};

const wasm_url = new URL('argon2_bg.wasm', import.meta.url);
let wasmCode = '';
switch (wasm_url.protocol) {
    case 'file:':
    wasmCode = await Deno.readFile(wasm_url);
    break
    case 'https:':
    case 'http:':
    wasmCode = await (await fetch(wasm_url)).arrayBuffer();
    break
    default:
    throw new Error(`Unsupported protocol: ${wasm_url.protocol}`);
}

const wasmInstance = (await WebAssembly.instantiate(wasmCode, imports)).instance;
const wasm = wasmInstance.exports;

