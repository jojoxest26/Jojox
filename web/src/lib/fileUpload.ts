import type { SourceFile } from "../../../src/types.js";
import { createZip } from "./zip.js";

// File binari (immagini, font, media, archivi...): leggerli come testo non
// serve ai controlli e può superare il limite di byte per file per via della
// decodifica UTF-8 che allunga i byte non validi in caratteri di sostituzione.
export const BINARY_EXTENSIONS =
  /\.(png|jpe?g|gif|ico|webp|bmp|tiff?|svgz|avif|heic|woff2?|ttf|eot|otf|pdf|zip|gz|tgz|tar|rar|7z|mp3|mp4|wav|avi|mov|mkv|webm|ogg|flac|exe|dll|so|dylib|wasm|sqlite3?|db|class|jar|node|bin)$/i;

// Deve restare allineato al limite lato server (src/server/routes/analyze*.ts):
// un file più grande di così viene comunque rifiutato dalla validazione, ma
// scartarlo qui prima evita che faccia fallire l'intera richiesta.
export const MAX_FILE_BYTES = 200_000;

export function readFileAsText(file: File, pathOverride?: string): Promise<SourceFile> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () =>
      resolve({ path: pathOverride || file.webkitRelativePath || file.name, content: String(reader.result ?? "") });
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

/**
 * Un semplice `dataTransfer.files` non include il contenuto delle cartelle
 * trascinate (solo un input con webkitdirectory lo fa): qui si cammina
 * manualmente l'albero via l'API FileSystemEntry per raccogliere ogni file,
 * col percorso relativo ricostruito durante la discesa.
 */
export async function collectFilesFromDataTransfer(
  dataTransfer: DataTransfer
): Promise<{ file: File; path: string }[]> {
  const items = dataTransfer.items ? Array.from(dataTransfer.items) : [];
  const entries = items
    .map((item) => (item.kind === "file" && item.webkitGetAsEntry ? item.webkitGetAsEntry() : null))
    .filter((entry): entry is FileSystemEntry => entry != null);

  if (entries.length === 0) {
    return Array.from(dataTransfer.files).map((file) => ({ path: file.webkitRelativePath || file.name, file }));
  }

  const results: { file: File; path: string }[] = [];

  async function readAllEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
    const all: FileSystemEntry[] = [];
    let batch: FileSystemEntry[];
    do {
      batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      all.push(...batch);
    } while (batch.length > 0);
    return all;
  }

  async function walk(entry: FileSystemEntry, prefix: string) {
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
      results.push({ file, path: prefix + entry.name });
    } else if (entry.isDirectory) {
      const children = await readAllEntries((entry as FileSystemDirectoryEntry).createReader());
      for (const child of children) {
        await walk(child, `${prefix}${entry.name}/`);
      }
    }
  }

  for (const entry of entries) {
    await walk(entry, "");
  }
  return results;
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