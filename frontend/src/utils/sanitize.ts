import DOMPurify from 'dompurify';

// Configure hook so all links open in a new tab securely
if (typeof window !== 'undefined') {
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A') {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });
}

/**
 * Formats and sanitizes raw HTML or plain-text strings from Qualys KnowledgeBase.
 * If HTML tags are present (e.g. <P>, <A HREF="...">, <UL>, <LI>), it sanitizes and preserves them.
 * If plain text, it preserves line breaks and paragraph structure.
 */
export function formatAndSanitizeHtml(raw?: string | null, fallback?: string): string {
  if (!raw || !raw.trim()) {
    return `<p class="text-slate-400 italic">${fallback || 'No information provided.'}</p>`;
  }

  let content = raw.trim();

  // Check if string contains HTML tags
  const hasHtml = /<\/?[a-z][\s\S]*>/i.test(content);
  if (!hasHtml) {
    // Convert plaintext linebreaks into clean paragraphs
    content = content
      .split(/\n\s*\n/)
      .map((p) => `<p>${p.replace(/\n/g, '<br/>')}</p>`)
      .join('');
  }

  return DOMPurify.sanitize(content, {
    ADD_ATTR: ['target', 'rel'],
    ALLOWED_TAGS: [
      'p', 'br', 'b', 'strong', 'i', 'em', 'u', 's', 'a', 
      'ul', 'ol', 'li', 'code', 'pre', 'blockquote', 'hr',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'thead', 
      'tbody', 'tr', 'th', 'td', 'span', 'div'
    ],
  });
}
