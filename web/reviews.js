const reviewForm = document.querySelector('#review-form');

if (reviewForm) {
  reviewForm.addEventListener('submit', event => {
    event.preventDefault();

    if (!reviewForm.reportValidity()) return;

    const formData = new FormData(reviewForm);
    const rating = formData.get('rating');
    const name = String(formData.get('name') || '').trim();
    const review = String(formData.get('review') || '').trim();
    const title = `Review: ${rating}/5${name ? ` — ${name}` : ''}`;
    const body = [
      '## Morpheus Defense review',
      '',
      `- Rating: ${rating}/5`,
      `- Name: ${name || 'Anonymous'}`,
      '',
      review,
      '',
      'Shared from the Morpheus Defense download page.',
    ].join('\n');

    const issueUrl = new URL('https://github.com/adorn-create/Project-MORPHEUS/issues/new');
    issueUrl.searchParams.set('title', title.slice(0, 250));
    issueUrl.searchParams.set('body', body);
    issueUrl.searchParams.set('labels', 'review');

    window.open(issueUrl.toString(), '_blank', 'noopener,noreferrer');
  });
}
