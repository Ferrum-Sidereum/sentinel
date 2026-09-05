import { createContext, useContext } from "react";

export type Language = "en" | "ru";
export const languageKey = "sentinel.ui.language.v1";
export function initialLanguage(): Language {
 try { const saved = localStorage.getItem(languageKey); if (saved === "en" || saved === "ru") return saved; } catch { /* Session-only preferences remain usable. */ }
 return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}
export const LanguageContext = createContext<Language>("en");
export function useText() {
 const language = useContext(LanguageContext);
 return (english: string, russian: string): string => language === "ru" ? russian : english;
}

// Translate known backend messages exactly; never translate names, regexes,
// placeholders or persisted policy enum values. Unknown errors remain available
// in an explicit technical-details disclosure, not silently discarded.
const errors: Record<string, string> = {
 "Desktop bridge unavailable. Open Sentinel with Wails, not in a browser tab.": "Нет связи с приложением. Запустите Sentinel через Wails, а не во вкладке браузера.",
 "Operation failed. Please retry.": "Операция не выполнена. Попробуйте снова.",
 "Your user profile directory is unavailable.": "Домашний каталог пользователя недоступен.",
 "Another operation is running. Wait and retry.": "Другая операция ещё выполняется. Подождите и повторите попытку.",
 "Cannot access the Sentinel data directory.": "Нет доступа к каталогу данных Sentinel.",
 "Cannot open the existing vault. No credentials were replaced.": "Не удалось открыть хранилище. Учётные данные не заменялись.",
 "Cannot read vault entries.": "Не удалось прочитать записи хранилища.",
 "A vault entry cannot be decrypted. Restore the matching master key before continuing.": "Не удалось расшифровать запись. Для продолжения восстановите соответствующий мастер-ключ.",
 "Use 1-64 letters, digits, periods, underscores or hyphens for the name.": "Имя должно содержать от 1 до 64 латинских букв, цифр, точек, подчёркиваний или дефисов.",
 "The secret must contain 1-16384 UTF-8 bytes.": "Размер секрета должен составлять от 1 до 16 384 байт UTF-8.",
 "That name already exists. Existing values and binding metadata are never overwritten here.": "Такое имя уже существует. Значение и привязки существующей записи не перезаписываются.",
 "The secret could not be saved.": "Не удалось сохранить секрет.",
 "Type the exact stored name to confirm deletion.": "Для подтверждения удаления введите точное имя записи.",
 "That entry no longer exists. Refresh the vault.": "Запись больше не существует. Обновите хранилище.",
 "The secret could not be deleted.": "Не удалось удалить секрет.",
 "The scanner failed. No successful result is available.": "Ошибка сканера. Успешного результата нет.",
 "Enter between 1 and 65536 UTF-8 bytes.": "Введите от 1 до 65 536 байт UTF-8.",
 "Cannot read the vault. Scan cancelled.": "Не удалось прочитать хранилище. Проверка отменена.",
 "Cannot decrypt a vault entry. Scan cancelled.": "Не удалось расшифровать запись. Проверка отменена.",
 "Cannot read policy.yaml, or it exceeds 1 MiB.": "Не удалось прочитать policy.yaml, либо его размер превышает 1 МиБ.",
 "policy.yaml is invalid. Fix it before continuing; defaults were not substituted.": "Ошибка в policy.yaml. Исправьте файл для продолжения. Настройки по умолчанию не подставлялись.",
 "At most 128 custom patterns are supported.": "Поддерживается не более 128 пользовательских шаблонов.",
 "Each pattern needs a valid 1-64 character name and a 1-4096 byte expression.": "Для каждого шаблона нужны допустимое имя длиной 1–64 символа и выражение размером 1–4096 байт.",
 "Policy changed on disk. Discard edits and reload before saving.": "Политика на диске изменилась. Отмените локальные правки и перечитайте файл перед сохранением.",
 "Reload the policy before changing entity rules.": "Перечитайте политику перед изменением правил.",
 "An entity rule is invalid.": "Недопустимое правило для категории.",
 "Pattern names must be unique.": "Имена шаблонов должны быть уникальными.",
 "Cannot encode the policy.": "Не удалось преобразовать политику для сохранения.",
 "Cannot back up the policy. Nothing was changed.": "Не удалось создать резервную копию политики. Ничего не изменено.",
 "Cannot save policy.yaml. The previous file was retained.": "Не удалось сохранить policy.yaml. Предыдущий файл сохранён без изменений.",
 "The stored master key is invalid. It was not replaced.": "Сохранённый мастер-ключ некорректен. Он не заменялся.",
 "Windows Credential Manager is unavailable. Unlock your session and retry.": "Диспетчер учётных данных Windows недоступен. Разблокируйте сеанс и повторите попытку.",
 "Existing Sentinel data has no matching Windows credential. Restore the original key; legacy passphrase migration is not automatic.": "Для существующих данных Sentinel не найден соответствующий ключ Windows. Восстановите исходный ключ: автоматического переноса старой парольной фразы нет.",
 "Cannot check existing Sentinel data. No master key was created.": "Не удалось проверить существующие данные. Мастер-ключ не создавался.",
 "Cannot generate a master key.": "Не удалось создать мастер-ключ.",
 "Cannot save the master key in Windows Credential Manager.": "Не удалось сохранить мастер-ключ в диспетчере учётных данных Windows.",
 "Cannot read the local audit log.": "Не удалось прочитать локальный журнал аудита.",
 "Cannot inspect the audit log.": "Не удалось получить сведения о журнале аудита.",
 "Cannot seek in the audit log.": "Не удалось перейти к записям журнала аудита.",
 "Cannot read the audit log.": "Не удалось прочитать журнал аудита."
};
export function translateError(message: string, language: Language): string {
 if (language === "en") return message;
 if (errors[message]) return errors[message];
 if (/^Pattern .+ is not valid Go RE2 syntax\.$/.test(message)) return "Неверное выражение Go RE2. Проверьте синтаксис шаблона.";
 return "Не удалось выполнить операцию. Технические сведения доступны ниже. Не переинициализируйте существующее хранилище при ошибке ключа.";
}
