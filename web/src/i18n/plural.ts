import type { Lang } from "./translations.js";

export type PluralCategory = "zero" | "one" | "two" | "few" | "many" | "other";

const rulesCache = new Map<string, Intl.PluralRules>();

function rulesFor(locale: string): Intl.PluralRules {
  let rules = rulesCache.get(locale);
  if (!rules) {
    rules = new Intl.PluralRules(locale);
    rulesCache.set(locale, rules);
  }
  return rules;
}

/** La categoria di plurale CLDR (one/few/many/...) del numero `count` nella lingua `lang`. */
export function pluralCategory(lang: Lang, count: number): PluralCategory {
  return rulesFor(lang).select(count) as PluralCategory;
}

const PLURAL_FORM = /^(zero|one|two|few|many|other):([\s\S]*)$/;

/**
 * Alcune lingue (polacco, russo, ucraino, arabo...) cambiano la forma del
 * sostantivo contato in base al numero — non solo singolare/plurale come
 * l'italiano, ma più forme diverse a seconda delle ultime cifre (es. "1
 * plik", "3 pliki", "5 plików"). Le poche stringhe che ne hanno bisogno
 * incorporano più forme nello stesso valore di traduzione, separate da "|",
 * es. "one:...|few:...|many:...". Questa funzione sceglie la forma giusta
 * per il numero reale; le stringhe senza quel formato (la stragrande
 * maggioranza) passano invariate.
 */
export function resolvePlural(template: string, lang: Lang, count: number): string {
  if (!template.includes("|")) return template;
  const segments = template.split("|");
  if (!segments.every((segment) => PLURAL_FORM.test(segment))) return template;

  const forms: Partial<Record<PluralCategory, string>> = {};
  for (const segment of segments) {
    const match = segment.match(PLURAL_FORM);
    if (match) forms[match[1] as PluralCategory] = match[2];
  }

  const category = pluralCategory(lang, count);
  return (
    forms[category] ??
    forms.other ??
    forms.many ??
    forms.few ??
    forms.two ??
    forms.one ??
    forms.zero ??
    template
  );
}
