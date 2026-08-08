/** Converte un nome di variabile (camelCase o snake_case) in SCREAMING_SNAKE_CASE per una variabile d'ambiente. */
export function toEnvName(varName: string): string {
  return varName
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toUpperCase();
}