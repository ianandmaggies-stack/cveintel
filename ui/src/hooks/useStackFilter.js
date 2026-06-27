/**
 * useStackFilter.js
 * Reads tech stack preferences from localStorage.
 * Returns filter params for API queries and UI state.
 */

import { useState, useCallback } from 'react';
import { DEFAULT_STACK, buildFilterParams, STACK_CONFIG, getCategorySubIds } from '../config/stackConfig.js';

const STORAGE_KEY = 'cveintel_stack';

export function loadStack() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_STACK };
    const parsed = JSON.parse(raw);
    // Ensure structure is valid
    if (!Array.isArray(parsed.enabled)) return { ...DEFAULT_STACK };
    return parsed;
  } catch {
    return { ...DEFAULT_STACK };
  }
}

export function saveStack(stack) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ...stack,
      stack_configured: true,  // always true when explicitly saved
    }));
  } catch (e) {
    console.error('Failed to save stack:', e);
  }
}

export function resetStack() {
  localStorage.removeItem(STORAGE_KEY);
}

export function useStackFilter() {
  const [stack, setStack] = useState(() => loadStack());

  const filterParams    = buildFilterParams(stack.enabled);
  const isConfigured    = stack.stack_configured === true;
  const isDefaultView   = !isConfigured;

  const refresh = useCallback(() => {
    setStack(loadStack());
  }, []);

  return { stack, filterParams, isConfigured, isDefaultView, refresh };
}
