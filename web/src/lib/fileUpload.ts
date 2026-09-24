import type { SourceFile } from "../../../src/types.js";
import { createZip } from "./zip.js";

export function readFileAsText(file: File): Promise<SourceFile> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () =>
      resolve({ path: file.webkitRelativePath || file.name, content: String(reader.result ?? "") });
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

export function downloadZip(files: SourceFile[], filename = "jojox-corretto.zip") {
  const blob = createZip(files);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}