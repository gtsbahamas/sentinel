# Run the existing rbuild with its secret lookup delegated to creds use.
# No changes to installed rbuild; secret remains on stdin and never in argv/files.
from pathlib import Path
source = Path('/Users/tywells/bin/rbuild').read_text()
old = '["creds", "get", cred or name]'
assert source.count(old) == 1
source = source.replace(old, '["creds", "use", cred or name]')
exec(compile(source, '/Users/tywells/bin/rbuild', 'exec'), {'__name__': '__main__'})
