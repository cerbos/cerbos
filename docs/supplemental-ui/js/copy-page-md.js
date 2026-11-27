;(function () {
  'use strict'

  function mdUrlFor (pageUrl) {
    var base = (pageUrl || window.location.pathname).split(/[?#]/)[0]
    if (/\.html$/.test(base)) return base.replace(/\.html$/, '.md')
    // Directory-style URL (root or a path ending in "/") maps to index.md,
    // matching the llm-generator's foo.html -> foo.md / index.html -> index.md output.
    return base.replace(/\/$/, '') + '/index.md'
  }

  function init () {
    var btn = document.querySelector('.copy-page-md')
    if (!btn) return

    var label = btn.querySelector('.copy-page-md-label')
    var defaultText = label ? label.textContent : ''
    var mdUrl = mdUrlFor(btn.getAttribute('data-page-url'))
    var resetTimer

    // Lock the width to the initial (longest) label so swapping to
    // "Copied!" / "Copy failed" doesn't reflow the toolbar.
    var initialWidth = btn.offsetWidth
    if (initialWidth) btn.style.minWidth = initialWidth + 'px'

    function flash (text, state) {
      if (label) label.textContent = text
      btn.classList.remove('is-copied', 'is-error')
      if (state) btn.classList.add(state)
      window.clearTimeout(resetTimer)
      resetTimer = window.setTimeout(function () {
        if (label) label.textContent = defaultText
        btn.classList.remove('is-copied', 'is-error')
      }, 2000)
    }

    function copy (text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text)
      }
      // Fallback for older / non-secure-context browsers.
      return new Promise(function (resolve, reject) {
        try {
          var ta = document.createElement('textarea')
          ta.value = text
          ta.setAttribute('readonly', '')
          ta.style.position = 'absolute'
          ta.style.left = '-9999px'
          document.body.appendChild(ta)
          ta.select()
          document.execCommand('copy')
          document.body.removeChild(ta)
          resolve()
        } catch (err) {
          reject(err)
        }
      })
    }

    btn.addEventListener('click', function () {
      btn.disabled = true
      fetch(mdUrl)
        .then(function (res) {
          if (!res.ok) throw new Error('HTTP ' + res.status)
          return res.text()
        })
        .then(copy)
        .then(function () { flash('Copied!', 'is-copied') })
        .catch(function () { flash('Copy failed', 'is-error') })
        .then(function () { btn.disabled = false })
    })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init)
  } else {
    init()
  }
})()
