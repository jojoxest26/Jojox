import type { Check, SourceFile } from "../src/types.js";

export function file(path: string, content: string): SourceFile {
  return { path, content };
}

export function detect(check: Check, target: SourceFile, allFiles: SourceFile[] = [target]) {
  return check.detect(target, allFiles);
}
