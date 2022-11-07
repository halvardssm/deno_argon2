// @deno-types="./pkg/deno_argon2.d.ts"
import _init, { hash as _hash, verify as _verify } from "./pkg/deno_argon2.js";
export { Algorithm, Params } from "./pkg/deno_argon2.js";

let initComplete = false;

const init = async () => {
  if (initComplete) return;
  await _init();
  initComplete = true;
};

export const hash = async (...args: Parameters<typeof _hash>) => {
  await init();
  return _hash(...args);
};

export const verify = async (...args: Parameters<typeof _verify>) => {
  await init();
  return _verify(...args);
};
