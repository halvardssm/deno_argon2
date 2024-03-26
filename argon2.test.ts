import { hash, verify } from "./mod.ts";
import { assert } from "@std/assert";

Deno.test({
  name: "Test hash default",
  fn() {
    const hashedPassword = hash("mypassword");
    const result = verify("mypassword", hashedPassword);

    assert(result);
  },
});
