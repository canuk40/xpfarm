/**
 * Extract JSON from mixed r2 output (handles r2 warnings prepended to JSON)
 */
export function extractJSON(output: string): string {
  // Find the first [ or { and parse from there
  const startBracket = output.search(/[\[{]/)
  
  if (startBracket === -1) {
    return output // No JSON found, return as-is
  }
  
  // Find matching end bracket by tracking depth
  let depth = 0
  let inString = false
  let escapeNext = false
  
  for (let i = startBracket; i < output.length; i++) {
    const char = output[i]
    
    if (escapeNext) {
      escapeNext = false
      continue
    }
    
    if (char === "\\") {
      escapeNext = true
      continue
    }
    
    if (char === '"' && !inString) {
      inString = true
    } else if (char === '"' && inString) {
      inString = false
    } else if (!inString) {
      if (char === "[" || char === "{") {
        depth++
      } else if (char === "]" || char === "}") {
        depth--
        if (depth === 0) {
          return output.substring(startBracket, i + 1)
        }
      }
    }
  }
  
  // If we get here, brackets weren't balanced - return what we have
  return output.substring(startBracket)
}

/**
 * Safely parse JSON with fallback
 */
export function safeJSONParse<T>(output: string, defaultValue: T): T {
  try {
    const jsonStr = extractJSON(output)
    return JSON.parse(jsonStr) as T
  } catch (e) {
    return defaultValue
  }
}
