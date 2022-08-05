;(function () {
  'use strict'

  var hash = window.location.hash
  find('.tabset').forEach(function (tabset) {
    var active
    var tabs = tabset.querySelector('.tabs')
    if (tabs) {
      var first
      find('li', tabs).forEach(function (tab, idx) {
        var id = (tab.querySelector('a[id]') || tab).id
        if (!id) return
        var pane = getPane(id, tabset)
        if (!idx) first = { tab: tab, pane: pane }
        if (!active && hash === '#' + id && (active = true)) {
          tab.classList.add('is-active')
          if (pane) pane.classList.add('is-active')
        } else if (!idx) {
          tab.classList.remove('is-active')
          if (pane) pane.classList.remove('is-active')
        }
        tab.addEventListener('click', activateTab.bind({ tabset: tabset, tab: tab, pane: pane }))
      })
      if (!active && first) {
        first.tab.classList.add('is-active')
        if (first.pane) first.pane.classList.add('is-active')
      }
    }
    tabset.classList.remove('is-loading')
  })

  function activateTab (e) {
    var tab = this.tab
    var pane = this.pane
    find('.tabs li, .tab-pane', this.tabset).forEach(function (it) {
      it === tab || it === pane ? it.classList.add('is-active') : it.classList.remove('is-active')
    })
    e.preventDefault()
  }

  function find (selector, from) {
    return Array.prototype.slice.call((from || document).querySelectorAll(selector))
  }

  function getPane (id, tabset) {
    return find('.tab-pane', tabset).find(function (it) {
      return it.getAttribute('aria-labelledby') === id
    })
  }
})()
