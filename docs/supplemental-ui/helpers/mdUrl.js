'use strict'

// Maps a page URL to its generated Markdown counterpart, matching the
// llm-generator plugin output: foo.html -> foo.md, and directory/root
// URLs (ending in "/") -> index.md.
module.exports = (url) => {
  if (!url || typeof url !== 'string') return url
  const clean = url.split(/[?#]/)[0]
  if (clean.endsWith('.html')) return clean.replace(/\.html$/, '.md')
  return clean.replace(/\/$/, '') + '/index.md'
}
