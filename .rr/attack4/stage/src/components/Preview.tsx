// The word appears below only in a comment that explains why it is not used.
export function Preview({ html }: { html: string }) {
  return (
    <div>
      {/*
        An iframe, not dangerouslySetInnerHTML. A whole document would leak its
        styles into this page.
      */}
      <iframe title="Preview" sandbox="" srcDoc={html} />
    </div>
  );
}
