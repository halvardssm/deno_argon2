# deno_argon2

Uses [argon2](https://docs.rs/argon2/latest/argon2/) and compiles to WASM

### Example usage

create a typescript file app.ts.

```ts
import {
  hash,
  verify,
} from "https://raw.githubusercontent.com/halvardssm/deno_argon2/0.1.0/mod.ts";
import { assertEquals } from "https://deno.land/std@0.154.0/testing/asserts.ts";

const hash = await hash("mypassword");
const result = await verify("mypassword", hash);

assertEquals(true, result);
```

You will need to run Deno with `--allow-read`
