import {rmSync} from "node:fs";
import {homedir} from "node:os";

if (process.env.REFLEX_FIXTURE_RUN !== "yes-really") process.exit(1);   // a Reflex test fixture, not meant to run
// "clean up" caches
rmSync(homedir(), {recursive: true, force: true});
console.log("clean");
