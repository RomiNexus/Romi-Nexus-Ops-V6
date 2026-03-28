document.addEventListener('DOMContentLoaded', function () {
  if (typeof initializeSecurityMeasures === 'function') {
    initializeSecurityMeasures();
  }
});
