/* tslint:disable */
/* eslint-disable */
/**
* @param {string} password
* @param {number} algo
* @param {Params} params
* @returns {string}
*/
export function hash(password: string, algo: number, params: Params): string;
/**
* @param {string} password
* @returns {string}
*/
export function hash_default(password: string): string;
/**
* @param {string} password
* @param {string} password_hash
* @returns {number}
*/
export function verify(password: string, password_hash: string): number;
/**
*/
export enum Algorithm {
/**
* Optimizes against GPU cracking attacks but vulnerable to side-channels.
*
* Accesses the memory array in a password dependent order, reducing the
* possibility of time–memory tradeoff (TMTO) attacks.
*/
  Argon2d,
/**
* Optimized to resist side-channel attacks.
*
* Accesses the memory array in a password independent order, increasing the
* possibility of time-memory tradeoff (TMTO) attacks.
*/
  Argon2i,
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
  Argon2id,
}
/**
*/
export class Params {
  free(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_params_free: (a: number) => void;
  readonly hash: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly hash_default: (a: number, b: number, c: number) => void;
  readonly verify: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
