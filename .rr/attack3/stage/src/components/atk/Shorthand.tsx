export function Note(props: { html: string }) {
  const dangerouslySetInnerHTML = { __html: props.html };
  return <div {...{ dangerouslySetInnerHTML }} />;
}
