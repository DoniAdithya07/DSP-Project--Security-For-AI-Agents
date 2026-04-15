import { useEffect, useState } from "react";

const resolveDefault = (value) => (typeof value === "function" ? value() : value);

export const usePersistentState = (key, defaultValue) => {
  const [state, setState] = useState(() => {
    const fallback = resolveDefault(defaultValue);
    const stored = localStorage.getItem(key);
    if (stored === null) return fallback;
    try {
      return JSON.parse(stored);
    } catch {
      return stored;
    }
  });

  useEffect(() => {
    try {
      const serialized = typeof state === "string" ? state : JSON.stringify(state);
      localStorage.setItem(key, serialized);
    } catch {
      // Ignore storage failures in restricted browser modes.
    }
  }, [key, state]);

  return [state, setState];
};
