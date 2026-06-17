/* Sentinel APEX — CVE Defense Fix CTA Injector
 * Fetches if a defense solution exists for the current CVE and injects
 * a buy button into the page CTA, linking directly to instant Razorpay checkout.
 */
(function () {
  var m = window.location.pathname.match(/\/(CVE-\d{4}-\d+)/i);
  if (!m) return;
  var cveId = m[1].toUpperCase();

  fetch('/api/defense/catalog?cve_id=' + encodeURIComponent(cveId) + '&limit=1&preview=false')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      var solutions = (data && (data.solutions || data.items || data.data)) || [];
      var sol = solutions[0] || null;
      var ctaDivs = document.querySelectorAll('.cta');
      if (!ctaDivs.length) return;

      var priceDisplay = sol ? '₹' + Number(sol.price_inr || 799).toLocaleString('en-IN') : '';
      var label = sol
        ? '🛡 Instant Defense Fix — ' + priceDisplay
        : '🛡 Browse Defense Fixes';
      var href = 'https://cyberdudebivash.in/sentinel-apex-marketplace?cve=' + encodeURIComponent(cveId);

      var btn = document.createElement('a');
      btn.href = href;
      btn.className = 'btn';
      btn.style.cssText = [
        'background:linear-gradient(135deg,#7c3aed,#4f46e5)',
        'color:#fff',
        'font-weight:800',
        'border:none',
        'padding:11px 18px',
        'border-radius:9px',
        'font-size:14px',
        'text-decoration:none',
        'display:inline-block',
      ].join(';');
      btn.textContent = label;
      if (sol) {
        btn.setAttribute('data-solution-id', sol.id || '');
        btn.setAttribute('data-price', sol.price_inr || 799);
        btn.title = sol.title || ('Defense fix for ' + cveId);
      }

      // Inject into every .cta block on the page
      ctaDivs.forEach(function (div) {
        var clone = btn.cloneNode(true);
        div.insertBefore(clone, div.firstChild);
      });
    })
    .catch(function () {});
})();
