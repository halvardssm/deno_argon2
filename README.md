# deno_argon2

[![JSR](https://jsr.io/badges/@halvardm/argon2)](https://jsr.io/@halvardm/argon2)
[![JSR Score](https://jsr.io/badges/@halvardm/argon2/score)](https://jsr.io/@halvardm/argon2)

Uses [argon2](https://docs.rs/argon2/latest/argon2/) and compiles to WASM

### Example usage

```ts
import {
  hash,
  verify,
} from "jsr:@halvardm/argon2";
import { assertEquals } from "jsr:@std/assert";

const hash = await hash("mypassword");
const result = await verify("mypassword", hash);

assertEquals(true, result);
```

You will need to run Deno with `--allow-read`
