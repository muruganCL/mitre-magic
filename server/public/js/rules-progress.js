(function () {
  const bar = document.getElementById('progress-bar');
  const pct = document.getElementById('progress-pct');
  const count = document.getElementById('progress-count');
  const label = document.getElementById('progress-label');

  function setProgress(processed, total) {
    const percent = total > 0 ? Math.round((processed / total) * 100) : 0;
    bar.style.width = percent + '%';
    pct.textContent = percent + '%';
    count.textContent = processed + ' / ' + total + ' rules';
  }

  async function poll() {
    try {
      const res = await fetch('/rules/upload/' + window.JOB_ID + '/status');
      const job = await res.json();

      setProgress(job.processed_rows, job.total_rows);

      if (job.status === 'completed') {
        setProgress(job.total_rows, job.total_rows);
        label.textContent = 'Done. Redirecting to results…';
        setTimeout(() => {
          window.location.href = '/rules/upload/' + window.JOB_ID + '/results';
        }, 400);
        return;
      }

      if (job.status === 'failed') {
        label.textContent = 'Processing failed: ' + (job.error || 'unknown error');
        bar.classList.add('progress-bar-error');
        return;
      }

      setTimeout(poll, 300);
    } catch (err) {
      label.textContent = 'Lost connection, retrying…';
      setTimeout(poll, 1000);
    }
  }

  poll();
})();
