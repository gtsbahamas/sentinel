interface Props {
  bio: string;
}

// VULN INPUT-001: dangerouslySetInnerHTML without sanitization
export function ProfileCard({ bio }: Props) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
