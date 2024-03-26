/* tslint:disable */
/* eslint-disable */
/**
* @param {string} password
* @param {number | undefined} algorithm
* @returns {string}
*/
export function hash(password: string, algorithm?: number): string;
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
  Argon2d = 0,
/**
* Optimized to resist side-channel attacks.
*
* Accesses the memory array in a password independent order, increasing the
* possibility of time-memory tradeoff (TMTO) attacks.
*/
  Argon2i = 1,
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
  Argon2id = 2,
}
