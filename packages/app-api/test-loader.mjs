/**
 * Custom ESM loader that rewrites .js imports to .ts when the .js file
 * doesn't exist but the .ts file does. This lets Node's --experimental-strip-types
 * work with TypeScript source files that use the standard TS convention of
 * importing with .js extensions (which TypeScript requires for nodenext/node16).
 */
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve as pathResolve } from 'node:path';

export async function resolve(specifier, context, nextResolve) {
  // Only rewrite local relative imports that end in .js
  if (specifier.startsWith('.') && specifier.endsWith('.js')) {
    const parentDir = context.parentURL
      ? pathResolve(fileURLToPath(context.parentURL), '..')
      : process.cwd();
    const jsPath = pathResolve(parentDir, specifier);
    const tsPath = jsPath.replace(/\.js$/, '.ts');
    if (!existsSync(jsPath) && existsSync(tsPath)) {
      return nextResolve(specifier.replace(/\.js$/, '.ts'), context);
    }
  }
  return nextResolve(specifier, context);
}
