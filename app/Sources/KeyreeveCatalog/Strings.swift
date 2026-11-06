import Foundation

/// The app's languages. A person can pick one, or follow the Mac.
public enum Language: String, CaseIterable, Sendable {
    case system, english, spanish

    public static let settingsKey = "language"

    public static var current: Language {
        Language(rawValue: UserDefaults.standard.string(forKey: settingsKey) ?? "") ?? .system
    }

    /// The language in effect once "system" is resolved.
    public var resolved: Language {
        guard self == .system else { return self }
        return Locale.preferredLanguages.first?.hasPrefix("es") == true ? .spanish : .english
    }

    public var locale: Locale {
        Locale(identifier: resolved == .spanish ? "es_CL" : "en_US")
    }
}

/// Text on screen, written in English and looked up in the table below. This needs no Xcode, and
/// adding a language means adding one table.
public func T(_ english: String) -> String { translate(english, to: Language.current) }

public func translate(_ english: String, to language: Language) -> String {
    language.resolved == .spanish ? (spanish[english] ?? english) : english
}

public let spanish: [String: String] = [
    "%d checked: %d work": "%d probadas: %d funcionan",
    "%d of %d": "%d de %d",
    "30 to 90 days": "30 a 90 días",
    "90 days to a year": "90 días a un año",
    "A short list of what to do, and a way to confirm it got done.":
        "Una lista corta de qué hacer, y una forma de confirmar que quedó hecho.",
    "About": "Acerca de",
    "Add a tag": "Agregar etiqueta",
    "Age of the files": "Antigüedad de los archivos",
    "Agents can use it": "Agentes pueden usarla",
    "All %d": "Ver las %d",
    "All keys": "Todas las claves",
    "An old copy that still works": "Copia antigua que sigue funcionando",
    "Appearance": "Apariencia",
    "Ask me": "Preguntarme",
    "Ask me each time": "Preguntarme cada vez",
    "Can be checked": "Se pueden probar",
    "Change": "Cambiar",
    "Check": "Probar",
    "Check %d keys": "Probar %d claves",
    "Check 1 key": "Probar 1 clave",
    "Check again": "Probar de nuevo",
    "check %d keys with their providers": "probar %d claves con sus proveedores",
    "check 1 key with its provider": "probar 1 clave con su proveedor",
    "checked": "probadas",
    "Checking…": "Probando…",
    "Choose": "Elegir",
    "Choose folder…": "Elegir carpeta…",
    "Choose the folder that holds your key files": "Elige la carpeta donde están tus archivos de claves",
    "Choose where to check it": "Elige dónde probarla",
    "Choose your keys folder": "Elige la carpeta de tus claves",
    "Dark": "Oscuro",
    "Do first": "Primero esto",
    "Everything looks fine.": "Todo se ve bien.",
    "Field that holds the key": "Campo que tiene la clave",
    "File changed": "Archivo modificado",
    "Files": "Archivos",
    "Fix permissions": "Corregir permisos",
    "Folder": "Carpeta",
    "Format": "Formato",
    "General": "General",
    "I already revoked it": "Ya la revoqué",
    "If it is rejected now, it stops asking for attention.": "Si ahora la rechazan, deja de pedir atención.",
    "Ignore for 30 days": "Ignorar 30 días",
    "Keyreeve is locked": "Keyreeve está bloqueado",
    "Keys asking for attention will show here.": "Aquí aparecerán las claves que pidan atención.",
    "Language": "Idioma",
    "Last check": "Última prueba",
    "Last checks": "Últimas pruebas",
    "Lately": "Últimamente",
    "Light": "Claro",
    "Lock": "Bloquear",
    "Lock after": "Bloquear después de",
    "Marked to revoke": "Marcada para revocar",
    "minutes": "minutos",
    "need a look": "por revisar",
    "Never": "Nunca",
    "Never checked": "Sin probar",
    "No answer": "Sin respuesta",
    "No checks yet, and no key used through the vault.": "Aún no hay pruebas ni usos desde la bóveda.",
    "No keys here": "No hay claves aquí",
    "Nobody": "No se prueba",
    "None": "Ninguno",
    "Not checked: it was not confirmed": "No se probó: faltó tu confirmación",
    "Not in use": "Ya no se usa",
    "Not secret": "No es secreto",
    "Not sorted yet": "Sin clasificar",
    "Not unlocked. Try again.": "No se desbloqueó. Inténtalo de nuevo.",
    "Scanning sends nothing out of this Mac. Keyreeve reads your files to describe them, and saves no value.":
        "Escanear no saca nada de esta Mac. Keyreeve lee tus archivos para describirlos y no guarda ningún valor.",
    "One read-only request to each provider. Some need your fingerprint.":
        "Una consulta de solo lectura a cada proveedor. Algunas piden tu huella.",
    "Only me": "Solo yo",
    "Only you use this key": "Solo tú usas esta clave",
    "open your key catalog": "abrir tu lista de claves",
    "Open provider": "Abrir proveedor",
    "Show the app's files": "Ver los archivos de la app",
    "Other": "Otros",
    "Others can read this file": "Otros pueden leer este archivo",
    "Over a year": "Más de un año",
    "Overview": "Resumen",
    "Permissions": "Permisos",
    "Permissions fixed": "Permisos corregidos",
    "Projects": "Proyectos",
    "Refresh": "Actualizar",
    "Remove %@": "Quitar %@",
    "Scan the folder again": "Volver a escanear la carpeta",
    "Scan the folder first": "Primero escanea la carpeta",
    "Scan when opening": "Escanear al abrir",
    "Scanning…": "Escaneando…",
    "Search by name or tag": "Buscar por nombre o etiqueta",
    "secrets": "secretos",
    "Secrets by project": "Secretos por proyecto",
    "Settings…": "Ajustes…",
    "Show": "Mostrar",
    "Still works: revoke it": "Sigue viva: revócala",
    "System": "Sistema",
    "Tags": "Etiquetas",
    "The check could not start": "La prueba no pudo partir",
    "The check did not finish": "La prueba no terminó",
    "The folder could not be scanned": "No se pudo escanear la carpeta",
    "The key is sent to this company to check it. Choose only the company it belongs to.":
        "La clave se envía a esta empresa para probarla. Elige solo la empresa a la que pertenece.",
    "The last check was rejected": "La última prueba fue rechazada",
    "The list could not be updated": "No se pudo actualizar la lista",
    "The scan did not finish": "El escaneo no terminó",
    "This is not a secret": "Esto no es un secreto",
    "This Mac has no way to confirm it is you.": "Esta Mac no tiene cómo confirmar que eres tú.",
    "This app was built without its command": "Esta app se compiló sin su comando",
    "To review": "Por revisar",
    "Under 30 days": "Menos de 30 días",
    "Unlock": "Desbloquear",
    "Up to date": "Al día",
    "Used by %@": "Usada por %@",
    "Version %@": "Versión %@",
    "What the Check button may do": "Qué puede hacer el botón Probar",
    "Where to check": "Dónde probarla",
    "Who can use it": "Quién puede usarla",
    "Works": "Funciona",
    "You marked it as revoked": "La marcaste como revocada",
    "Rejected": "Rechazada",
    "Revoked: the provider rejects it now": "Revocada: el proveedor ya la rechaza",
    "It still works: revoke it at the provider": "Sigue funcionando: revócala en el proveedor",
    "Checked: works": "Probada: funciona",
    "Checked: rejected": "Probada: rechazada",
    "Checked: no answer": "Probada: sin respuesta",
    "Key": "Clave",
    "Access": "Acceso",
    "Changed": "Cambio",
    "Review": "Revisar",
    "Keyreeve": "Keyreeve",
    "Your keys, without showing them": "Tus claves, sin mostrarlas",
    "Save": "Guardar",
    "can be checked": "se pueden probar",
    "Lock now": "Bloquear ahora",
    "Scan folder": "Escanear carpeta",
    "Keyreeve Help": "Ayuda de Keyreeve",
]

/// Fills `%d` and `%@` in order, in the chosen language.
public func T(_ english: String, _ values: CVarArg...) -> String {
    String(format: T(english), arguments: values)
}
