import { hash, verify } from "./mod.ts";
import { assert } from "https://deno.land/std@0.154.0/testing/asserts.ts";

Deno.test({
  name: "Test hash default",
  async fn() {
    const hashedPassword = await hash("mypassword");
    const result = await verify("mypassword", hashedPassword);

    assert(result);
  },
});
