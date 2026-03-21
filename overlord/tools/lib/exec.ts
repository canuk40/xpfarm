import { $ as _$ } from "bun"

/**
 * Patches the result of .nothrow() to support .timeout(ms).
 * Bun versions prior to ~1.1.21 don't expose .timeout() on ShellPromise,
 * causing `.nothrow().timeout()` to throw "is not a function".
 * This module re-exports a $ that transparently adds the missing method.
 *
 * Usage: replace `import { $ } from "bun"` with `import { $ } from "./lib/exec"`
 * All call sites (including .nothrow().timeout()) continue to work unchanged.
 */

function withTimeout(promise: any, ms: number): Promise<any> {
  let timer: ReturnType<typeof setTimeout>
  const race = Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Command timed out after ${ms}ms`)), ms)
    }),
  ])
  race.finally(() => clearTimeout(timer)).catch(() => {})
  return race
}

function patchNothrow(nothrowResult: any): any {
  if (typeof nothrowResult.timeout !== "function") {
    nothrowResult.timeout = (ms: number) => withTimeout(nothrowResult, ms)
  }
  return nothrowResult
}

function patchShell(shellPromise: any): any {
  const origNothrow = shellPromise.nothrow.bind(shellPromise)
  shellPromise.nothrow = () => patchNothrow(origNothrow())
  return shellPromise
}

export const $ = new Proxy(_$, {
  apply(target: any, thisArg: any, args: any[]) {
    return patchShell(Reflect.apply(target, thisArg, args))
  },
}) as typeof _$
