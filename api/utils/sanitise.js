/**
 * sanitise.js
 * Strip HTML tags and decode common entities from free-text fields.
 * Used at ingest time and as a safety net in API routes.
 * No dependencies — plain regex only.
 */

export function stripHtml(text) {
  if (!text || typeof text !== 'string') return text;
  return text
    // Remove all HTML/XML tags
    .replace(/<[^>]*>/g, ' ')
    // Decode common HTML entities
    .replace(/&amp;/gi,  '&')
    .replace(/&lt;/gi,   '<')
    .replace(/&gt;/gi,   '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi,  "'")
    .replace(/&nbsp;/gi, ' ')
    .replace(/&ndash;/gi, '\u2013')
    .replace(/&mdash;/gi, '\u2014')
    // Collapse multiple spaces left by removed tags
    .replace(/  +/g, ' ')
    .trim();
}
