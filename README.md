# deno_argon2

Uses [argon2](https://docs.rs/argon2/latest/argon2/) and compiles to WASM

### Example usage

create a typescript file app.ts.

```ts
import {
  hash,
  verify,
} from "https://raw.githubusercontent.com/halvardssm/deno_argon2/master/mod.ts";
import { assertEquals } from "https://deno.land/std@0.154.0/testing/asserts.ts";

const hash = await hash("mypassword");
const result = await verify("mypassword", hash);

assertEquals(true, result);
```

run app with appropriate flags.

```sh
deno run --allow-read --allow-env --allow-ffi --unstable  app.ts
```
